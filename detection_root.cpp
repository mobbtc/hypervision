#include "detection_root.h"
#include "echo_integration/runtime.h"
#include <thread>
#include <future>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include "utils/logger/logger.h"
#include "utils/crypt/crypto_init.h"
#include "scan_api/telemetry_v2.hpp"
#include "scan_api/telemetry_v2_keys.hpp"
#include "utils/protection/integrity_heartbeat.hpp"

std::unique_ptr<c_scanapi> c_detection::scan_api = nullptr;

class thread_pool
{
public:
    explicit thread_pool ( size_t threads )
    {
        for ( size_t i = 0; i < threads; ++i )
        {
            workers.emplace_back ( [this] {
                for ( ;;)
                {
                    std::function<void ( )> task;

                    {
                        std::unique_lock<std::mutex> lock ( queue_mutex );
                        condition.wait ( lock , [this] { return stop || !tasks.empty ( ); } );
                        if ( stop && tasks.empty ( ) ) return;
                        task = std::move ( tasks.front ( ) );
                        tasks.pop ( );
                    }

                    task ( );
                }
            } );
        }
    }

    ~thread_pool ( )
    {
        {
            std::unique_lock<std::mutex> lock ( queue_mutex );
            stop = true;
        }
        condition.notify_all ( );
        for ( std::thread& worker : workers ) worker.join ( );
    }

    template<class F>
    std::future<void> enqueue ( F&& f )
    {
        auto task = std::make_shared<std::packaged_task<void ( )>> ( std::forward<F> ( f ) );
        std::future<void> res = task->get_future ( );
        {
            std::unique_lock<std::mutex> lock ( queue_mutex );
            tasks.emplace ( [ task ] ( ) { ( *task )( ); } );
        }
        condition.notify_one ( );
        return res;
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void ( )>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop = false;
};

std::string c_detection::get_stage_message ( int stage_number ) {
    static const std::string messages [ 13 ]
    {
         ( xorstr_("Initializing scan...")),
         ( xorstr_("Scanning file paths, Windows Artifacts...")),
         ( xorstr_("Analysing data for cheat traces...") ),
         ( xorstr_("Checking Windows Artifacts for bypass method traces...") ),
         ( xorstr_("Checking accessible memory for cheat traces...") ),
         ( xorstr_("Scanning for custom strings...") ),
         ( xorstr_("Authenticating devices in Windows Artifacts...") ),
         ( xorstr_("Checking system safety...") ),
         ( xorstr_("Checking Windows Artifacts for application usage traces...") ),
         ( xorstr_("Performing game specific checks...") ),
         ( xorstr_("Analysing all the gathered data for cheats, bypasses... This may take a while...") ),
         ( xorstr_("Completing scan, generating & uploading results")),
         ( xorstr_("Uploading logs, please wait..."))
    };
    if ( stage_number >= 1 && stage_number <= 13 ) return messages [ stage_number - 1 ];
    return  ( xorstr_("Scanning...") );
}

void c_detection::heartbeat_thread ( const std::string& pin , std::atomic<bool>& running )
{
    auto& v2 = telemetry_v2::shared_session ( );

    CURL* curl = nullptr;
    const std::string url  = xorstr_("http://127.0.0.1:3000/auth/api/scanning/ping/") + pin;

    auto make_legacy_handle = [ & ] ( ) -> CURL* {
        CURL* h = curl_easy_init ( );
        if ( !h ) return nullptr;
        curl_easy_setopt ( h , CURLOPT_URL , url.c_str ( ) );
        curl_easy_setopt ( h , CURLOPT_POST , 1L );
        curl_easy_setopt ( h , CURLOPT_POSTFIELDS , "" );
        curl_easy_setopt ( h , CURLOPT_SSL_VERIFYPEER , 0L );
        curl_easy_setopt ( h , CURLOPT_SSL_VERIFYHOST , 0L );
        curl_easy_setopt ( h , CURLOPT_FOLLOWLOCATION , 0L );
        curl_easy_setopt ( h , CURLOPT_MAXREDIRS , 0L );
        curl_easy_setopt ( h , CURLOPT_PROXY , "" );
        curl_easy_setopt ( h , CURLOPT_NOPROXY , xorstr_("*") );
        curl_easy_setopt ( h , CURLOPT_CONNECTTIMEOUT , 10L );
        curl_easy_setopt ( h , CURLOPT_TIMEOUT , 15L );
        curl_easy_setopt ( h , CURLOPT_NOSIGNAL , 1L );
        return h;
    };

    while ( running )
    {
        if ( v2.is_open ( ) )
        {
            ( void ) v2.send_heartbeat ( );
        }
        else
        {
            if ( !curl ) curl = make_legacy_handle ( );
            if ( curl ) ( void ) curl_easy_perform ( curl );
        }

        for ( int i = 0; i < 10 && running; ++i ) std::this_thread::sleep_for ( std::chrono::seconds ( 1 ) );
    }
    if ( curl ) curl_easy_cleanup ( curl );
}

void c_detection::start_scan ( )
{
    echo_integration::reset();
    echo_integration::metrics.clear();
    echo_integration::inventory.clear();
    CryptoInit::EnsureInitialized ( );

    detect.scan_started = true;

    auto running = std::make_shared<std::atomic<bool>>(true);

    struct stop_heartbeat_guard {
        std::shared_ptr<std::atomic<bool>> flag;
        ~stop_heartbeat_guard() {
            if (flag) flag->store(false, std::memory_order_release);
        }
    } _hb_guard{ running };

    std::thread hb_thread ( [ running ] ( )
    {
        heartbeat_thread ( detect.pin , *running );
    } );
    hb_thread.detach ( );

    if ( !scan_api ) scan_api = std::make_unique<c_scanapi> ( xorstr_("http://127.0.0.1:3000/auth") , detect.pin );

    if ( !scan_api->start_scan ( ) ) return;

    Logger::instance ( ).ensure_guard_seeded ( );

    {
        const auto seed_snap = integrity_snapshot::capture ( );
        char seed_buf[512];
        int n = _snprintf_s ( seed_buf , _TRUNCATE ,
            xorstr_("{\"type\":\"INTEGRITY_SEED\",\"bits\":%u,\"bad_mods\":%u,\"bad_drv\":%u,\"mod_count\":%u,\"drv_count\":%u,\"boot\":%llu}") ,
            seed_snap.bits , seed_snap.bad_modules , seed_snap.bad_drivers ,
            seed_snap.module_count , seed_snap.driver_count ,
            static_cast<unsigned long long> ( seed_snap.boot_time_seconds ) );
        if ( n > 0 ) {
            uint32_t seed_seq = 0;
            uint8_t  seed_tag[log_tamper_guard::chain_tag_len] = {};
            log_tamper_guard::instance ( ).append (
                std::string_view ( seed_buf , static_cast<size_t> ( n ) ) , seed_seq , seed_tag );
        }
    }

    integrity_heartbeat::instance ( ).start ( 5 );

    size_t num_threads = std::thread::hardware_concurrency ( );
    thread_pool pool ( num_threads > 0 ? num_threads : 8 );
    std::vector<std::future<void>> futures;

    utils->check_server_status ( );

    std::atomic<size_t> completed_tasks { 0 };
    std::vector<echo_integration::Module> modules;
    auto register_module = [&](const char* id, const char* category, const char* sources,
                               std::function<void()> run) {
        echo_integration::Module m;
        m.id=id; m.category=category; m.sources=sources; m.run=std::move(run);
        // Legacy metadata remains explicitly unknown until its implementation is audited.
        if (!echo_integration::policy.disabled.count(id)) modules.push_back(std::move(m));
    };


    if ( detect.server_online && !detect.scanned )
    {
        if ( c_test->is_test_signing_enabled ( ) )
        {
            LOG ( DETECTION , xorstr_("N/A") ) << xorstr_("Test Signing Is Enabled");
            LOG ( INFO , xorstr_("N/A") ) << xorstr_("Scan will not proceed; critical detections found");
            Logger::instance ( ).flush_logs ( );
            detect.scanned = true;
            return;
        }

    
#ifndef DETECT_FORTNITE

        register_module("c_usn_journal_size.start_usn_journal_size_detection", "legacy", "unknown", [this] { c_usn_journal_size->start_usn_journal_size_detection(); });
        register_module("c_powershell_commands_ran.start_powershell_evtx_commands", "powershell", "windows_event_log", [this] { c_powershell_commands_ran->start_powershell_evtx_commands(); });
        register_module("c_diffd.start_diff_drive_detection", "legacy", "unknown", [this] { c_diffd->start_diff_drive_detection(); });
        register_module("c_club.start_club44_check", "legacy", "unknown", [this] { c_club->start_club44_check(); });
        register_module("c_asar.asar_checks", "legacy", "unknown", [this] { c_asar->asar_checks(); });
        register_module("c_wmi.start_wmi", "legacy", "unknown", [this] { c_wmi->start_wmi(); });
        register_module("c_task2.start_taskschedule_checks", "legacy", "unknown", [this] { c_task2->start_taskschedule_checks(); });

        register_module("c_sus_threads.start_suspeced_threads_detection", "legacy", "unknown", [this] { c_sus_threads->start_suspeced_threads_detection(); });
        register_module("c_cleared_evt.start_cleared_eventlog", "legacy", "unknown", [this] { c_cleared_evt->start_cleared_eventlog(); });
        register_module("c_bam.start_bam_state_detection", "legacy", "unknown", [this] { c_bam->start_bam_state_detection(); });
        register_module("c_mod_check.start_modified_check", "legacy", "unknown", [this] { c_mod_check->start_modified_check(); });
        register_module("c_injdll.start_opensavemidlmru_scan", "legacy", "unknown", [this] { c_injdll->start_opensavemidlmru_scan(); });
        register_module("c_res_ser.start_restarted_services_check", "legacy", "unknown", [this] { c_res_ser->start_restarted_services_check(); });
        register_module("c_term_ser.StartTerminationCheck", "legacy", "unknown", [this] { c_term_ser->StartTerminationCheck(); });

        register_module("c_usnjrnl2.start_usn_modified2", "legacy", "unknown", [this] { c_usnjrnl2->start_usn_modified2(); });
        register_module("c_time.start_timechange", "legacy", "unknown", [this] { c_time->start_timechange(); });
        register_module("c_dllh.start_dllh_scan", "legacy", "unknown", [this] { c_dllh->start_dllh_scan(); });
        register_module("c_peinj.start_pe_scan", "legacy", "unknown", [this] { c_peinj->start_pe_scan(); });
        register_module("c_peinj2.start_pe_injection_2_scan", "legacy", "unknown", [this] { c_peinj2->start_pe_injection_2_scan(); });
        register_module("c_h_and_p.start_hosts_and_prefetch", "legacy", "unknown", [this] { c_h_and_p->start_hosts_and_prefetch(); });
        register_module("c_powershell_logsize.start_powershell_logsize_check", "legacy", "unknown", [this] { c_powershell_logsize->start_powershell_logsize_check(); });

        register_module("c_powershell_profiles.checkProfiles", "legacy", "unknown", [this] { c_powershell_profiles->checkProfiles(); });
        register_module("c_regscan.start_Regsitry_scan", "legacy", "unknown", [this] { c_regscan->start_Regsitry_scan(); });
        register_module("c_prefbp.start_prefetch_bypass_check", "legacy", "unknown", [this] { c_prefbp->start_prefetch_bypass_check(); });
        register_module("c_prefint.start_prefetch_integrity", "legacy", "unknown", [this] { c_prefint->start_prefetch_integrity(); });
        register_module("c_evt_byp.start_eventlog_bypass", "legacy", "unknown", [this] { c_evt_byp->start_eventlog_bypass(); });
        register_module("c_cpl.CheckCPLBypass", "legacy", "unknown", [this] { c_cpl->CheckCPLBypass(); });
        register_module("c_msi.CheckMSIBypass", "legacy", "unknown", [this] { c_msi->CheckMSIBypass(); });
        register_module("c_reg.CheckREGBypass", "legacy", "unknown", [this] { c_reg->CheckREGBypass(); });
        register_module("c_inf.CheckINFBypass", "legacy", "unknown", [this] { c_inf->CheckINFBypass(); });
         
    #endif

    #ifdef DETECT_MINECRAFT

        register_module("c_atlas.start_atlas_trace_scan", "memory", "process_memory,modules,threads", [this] { c_atlas->start_atlas_trace_scan(); });

    #endif

    #if defined(DETECT_MINECRAFT) || defined(DETECT_FIVEM)

        register_module("c_fat32_2.start_fat32_2_modification_check", "legacy", "unknown", [this] { c_fat32_2->start_fat32_2_modification_check(); });
        register_module("c_fat32.start_fat32_modification_check", "legacy", "unknown", [this] { c_fat32->start_fat32_modification_check(); });
        register_module("c_junc.start_junc_scan", "legacy", "unknown", [this] { c_junc->start_junc_scan(); });

    #endif

        register_module("c_usn_journal_modified.start_usn_journal_modified_check", "legacy", "unknown", [this] { c_usn_journal_modified->start_usn_journal_modified_check(); });
        register_module("c_executed_files.start_executed_file_checks", "legacy", "unknown", [this] { c_executed_files->start_executed_file_checks(); });
        register_module("c_device_rm.start_dev_rm_checks", "legacy", "unknown", [this] { c_device_rm->start_dev_rm_checks(); });
        register_module("c_created_disk_part.start_created_part_checks", "legacy", "unknown", [this] { c_created_disk_part->start_created_part_checks(); });
        register_module("c_deleted_disk_part.start_deleted_part_checks", "legacy", "unknown", [this] { c_deleted_disk_part->start_deleted_part_checks(); });
        register_module("c_recycle_bin_modified.start_recycle_bin_modified_checks", "legacy", "unknown", [this] { c_recycle_bin_modified->start_recycle_bin_modified_checks(); });
        register_module("c_service.start_service_checks", "drivers", "service_control_manager,code_integrity", [this] { c_service->start_service_checks(); });
        register_module("c_ahk.start_ahk_bypass_detections", "legacy", "unknown", [this] { c_ahk->start_ahk_bypass_detections(); });
        register_module("c_prefcheck.start_enableprefetcherdeletion", "legacy", "unknown", [this] { c_prefcheck->start_enableprefetcherdeletion(); });
        register_module("c_letvol.start_letterless_volume_check", "legacy", "unknown", [this] { c_letvol->start_letterless_volume_check(); });
        register_module("c_usbbypass.start_usb_bypass_check", "legacy", "unknown", [this] { c_usbbypass->start_usb_bypass_check(); });
        register_module("c_usnbypasschecks.start_usn_bypass_checks", "legacy", "unknown", [this] { c_usnbypasschecks->start_usn_bypass_checks(); });

        register_module("c_vpn.start_vpn_detection", "legacy", "unknown", [this] { c_vpn->start_vpn_detection(); });
        register_module("c_install.print_install_date_and_elapsed_time", "legacy", "unknown", [this] { c_install->print_install_date_and_elapsed_time(); });
        register_module("c_pc_start.start_pc_start_time_check", "legacy", "unknown", [this] { c_pc_start->start_pc_start_time_check(); });
        register_module("c_sy.start_systeminfo_scan", "legacy", "unknown", [this] { c_sy->start_systeminfo_scan(); });
        register_module("c_tone.term_onedrive", "legacy", "unknown", [this] { c_tone->term_onedrive(); });
        register_module("c_cb.start_cmd_and_bat_detection", "legacy", "unknown", [this] { c_cb->start_cmd_and_bat_detection(); });
        register_module("c_py_ex.start_python_detection", "legacy", "unknown", [this] { c_py_ex->start_python_detection(); });
        register_module("c_vbs.start_vbs_detection", "legacy", "unknown", [this] { c_vbs->start_vbs_detection(); });
        register_module("c_dma_pads.start_dma_pads", "legacy", "unknown", [this] { c_dma_pads->start_dma_pads(); });
        register_module("c_dma_protection.start_dma_protection", "legacy", "unknown", [this] { c_dma_protection->start_dma_protection(); });
        register_module("c_nvidia_patch.CheckNvidiaDriverPatch", "legacy", "unknown", [this] { c_nvidia_patch->CheckNvidiaDriverPatch(); });

        register_module("c_browsers.start_browser_checks", "legacy", "unknown", [this] { c_browsers->start_browser_checks(); });
        register_module("c_bam_install.detect_bam_cleaned", "legacy", "unknown", [this] { c_bam_install->detect_bam_cleaned(); });
        register_module("c_cpowershell.start_powershell_scans", "legacy", "unknown", [this] { c_cpowershell->start_powershell_scans(); });
        register_module("c_delbam.start_del_bam", "legacy", "unknown", [this] { c_delbam->start_del_bam(); });
        register_module("c_delregkeys.start_deleted_reg_keys_check", "legacy", "unknown", [this] { c_delregkeys->start_deleted_reg_keys_check(); });
        register_module("c_cfg_check.start_cfg_check", "legacy", "unknown", [this] { c_cfg_check->start_cfg_check(); });
        register_module("c_discacc.ScanForDiscordUsernames", "legacy", "unknown", [this] { c_discacc->ScanForDiscordUsernames(); });
        register_module("c_cdump.start_crashdump_checks", "legacy", "unknown", [this] { c_cdump->start_crashdump_checks(); });
        register_module("c_efidet.start_efi_detections", "legacy", "unknown", [this] { c_efidet->start_efi_detections(); });
        register_module("c_efi_mb.start_efi_measured_boot", "efi", "firmware,tpm,efi_partition", [this] { c_efi_mb->start_efi_measured_boot(); });
        register_module("c_prefdel.start_deleted_prefetch", "legacy", "unknown", [this] { c_prefdel->start_deleted_prefetch(); });
        
        register_module("c_lsass.start_lsass_scan", "legacy", "unknown", [this] { c_lsass->start_lsass_scan(); });
        register_module("c_pcasvc.start_pca_scan", "legacy", "unknown", [this] { c_pcasvc->start_pca_scan(); });
        register_module("c_usnjrnl_ex.start_scan_ex", "legacy", "unknown", [this] { c_usnjrnl_ex->start_scan_ex(); });
        register_module("c_evt_exp.start_eventlog_exploit_check", "legacy", "unknown", [this] { c_evt_exp->start_eventlog_exploit_check(); });
        register_module("c_yara.start_yara_scan", "yara", "files,crash_dumps", [this] { c_yara->start_yara_scan(); });
        register_module("c_prefinj.start_prefetch_injections", "legacy", "unknown", [this] { c_prefinj->start_prefetch_injections(); });
        register_module("c_adminran.start_files_ran_with_admin", "legacy", "unknown", [this] { c_adminran->start_files_ran_with_admin(); });
        register_module("c_commands3.start_commands_3", "legacy", "unknown", [this] { c_commands3->start_commands_3(); });
        register_module("c_ads.start_sus_ads", "legacy", "unknown", [this] { c_ads->start_sus_ads(); });
        register_module("c_autoruns.start_autoruns_detection", "legacy", "unknown", [this] { c_autoruns->start_autoruns_detection(); });

        register_module("c_dns.start_dns_scan", "legacy", "unknown", [this] { c_dns->start_dns_scan(); });
        register_module("c_compilation.compilation_scan", "legacy", "unknown", [this] { c_compilation->compilation_scan(); });
        register_module("c_usnjrnl.start_usn_scan", "usn", "usn_journal", [this] { c_usnjrnl->start_usn_scan(); });
        register_module("c_exe_pf.start_exe_pf_scan", "legacy", "unknown", [this] { c_exe_pf->start_exe_pf_scan(); });
        register_module("c_explorer_strings.start_explorer_scan", "legacy", "unknown", [this] { c_explorer_strings->start_explorer_scan(); });
        register_module("c_amc.start_amcache_scan", "legacy", "unknown", [this] { c_amc->start_amcache_scan(); });
        register_module("c_ss.start_ss_detection", "legacy", "unknown", [this] { c_ss->start_ss_detection(); });
        register_module("c_dbu.start_windb_urls", "legacy", "unknown", [this] { c_dbu->start_windb_urls(); });
        register_module("c_windef.QueryDefenderHistory", "defender", "defender_events,mplog", [this] { c_windef->QueryDefenderHistory(); });
        register_module("c_vhd.start_vhd_detection", "legacy", "unknown", [this] { c_vhd->start_vhd_detection(); });
        register_module("c_luascripts.start_luascripts_scan", "legacy", "unknown", [this] { c_luascripts->start_luascripts_scan(); });
        register_module("c_commands2.start_commands2", "legacy", "unknown", [this] { c_commands2->start_commands2(); });
        register_module("c_anydesk.start_anydesk_scan", "legacy", "unknown", [this] { c_anydesk->start_anydesk_scan(); });
        register_module("c_saved.start_saved_files", "lnk", "shell_links,opensave_mru", [this] { c_saved->start_saved_files(); });

        register_module("c_cdps.start_dps_scan", "legacy", "unknown", [this] { c_cdps->start_dps_scan(); });
        register_module("c_cdiag.start_diag_scan", "legacy", "unknown", [this] { c_cdiag->start_diag_scan(); });
        register_module("c_csys.start_sysmain_scan", "legacy", "unknown", [this] { c_csys->start_sysmain_scan(); });
        register_module("c_csgrm.start_sgrm_scan", "legacy", "unknown", [this] { c_csgrm->start_sgrm_scan(); });
        register_module("c_sgrm2.start_sgrm2_scan", "legacy", "unknown", [this] { c_sgrm2->start_sgrm2_scan(); });
        register_module("c_cschedule.start_schedule_scan", "legacy", "unknown", [this] { c_cschedule->start_schedule_scan(); });
        register_module("c_capp.start_appinfo_scan", "legacy", "unknown", [this] { c_capp->start_appinfo_scan(); });
        register_module("c_mps.start_mps_scan", "legacy", "unknown", [this] { c_mps->start_mps_scan(); });
        register_module("c_cmsmpeng.start_mpssvc_scan", "legacy", "unknown", [this] { c_cmsmpeng->start_mpssvc_scan(); });
        register_module("c_ccrypt.start_cryptsvc_scan", "legacy", "unknown", [this] { c_ccrypt->start_cryptsvc_scan(); });
        register_module("c_cdusm.start_dusm_scan", "legacy", "unknown", [this] { c_cdusm->start_dusm_scan(); });
        register_module("c_clogi.start_clogitech_scan", "legacy", "unknown", [this] { c_clogi->start_clogitech_scan(); });
        register_module("c_discord.start_discord_scan", "legacy", "unknown", [this] { c_discord->start_discord_scan(); });
        register_module("c_chrome.start_chrome_scan", "legacy", "unknown", [this] { c_chrome->start_chrome_scan(); });
        register_module("c_edge.start_edge_scan", "legacy", "unknown", [this] { c_edge->start_edge_scan(); });
        register_module("c_brave.start_brave_scan", "legacy", "unknown", [this] { c_brave->start_brave_scan(); });
        register_module("c_opera.start_opera_scan", "legacy", "unknown", [this] { c_opera->start_opera_scan(); });
        register_module("c_vivaldi.start_vivaldi_scan", "legacy", "unknown", [this] { c_vivaldi->start_vivaldi_scan(); });
        register_module("c_firefox.start_firefox_scan", "legacy", "unknown", [this] { c_firefox->start_firefox_scan(); });
        register_module("c_cfivem.start_cfivem_scan", "legacy", "unknown", [this] { c_cfivem->start_cfivem_scan(); });
        register_module("c_cevt.start_evt_scan", "legacy", "unknown", [this] { c_cevt->start_evt_scan(); });
        register_module("c_ctask.start_task_scan", "legacy", "unknown", [this] { c_ctask->start_task_scan(); });
        register_module("c_csi.start_si_scan", "legacy", "unknown", [this] { c_csi->start_si_scan(); });
        register_module("c_crtb.start_runtimebroker_scan", "legacy", "unknown", [this] { c_crtb->start_runtimebroker_scan(); });
        register_module("c_camcache.ProcessAmcache", "legacy", "unknown", [this] { c_camcache->ProcessAmcache(); });

#ifdef DETECT_MINECRAFT

        register_module("c_cjavaw.start_cjavaw_scan", "legacy", "unknown", [this] { c_cjavaw->start_cjavaw_scan(); });
        register_module("c_winmg.start_winmg_scan", "legacy", "unknown", [this] { c_winmg->start_winmg_scan(); });
        register_module("c_jvmarg.start_jvm_arg_scan", "legacy", "unknown", [this] { c_jvmarg->start_jvm_arg_scan(); });
        register_module("c_javainj.start_java_injection_scan", "legacy", "unknown", [this] { c_javainj->start_java_injection_scan(); });
#endif

    #if defined(DETECT_FORTNITE) || defined(DETECT_FIVEM) || defined(DETECT_SIEGE) || defined(DETECT_FREEFIRE)

            register_module("c_fusers.start_hdmifuser_scan", "legacy", "unknown", [this] { c_fusers->start_hdmifuser_scan(); });
            register_module("c_ddc.start_ddc_scan", "legacy", "unknown", [this] { c_ddc->start_ddc_scan(); });
            register_module("c_dma.start_pci_scanning", "legacy", "unknown", [this] { c_dma->start_pci_scanning(); });

    #endif

    #ifdef DETECT_SIEGE

            register_module("c_r6alts.start_r6alt_scan", "legacy", "unknown", [this] { c_r6alts->start_r6alt_scan(); });

    #endif

    #ifdef DETECT_FORTNITE

            register_module("c_epicalts.start_epic_alt_scan", "legacy", "unknown", [this] { c_epicalts->start_epic_alt_scan(); });

    #endif

    #ifdef DETECT_RUST

            register_module("c_steam_alt.start_steam_alt_detection", "legacy", "unknown", [this] { c_steam_alt->start_steam_alt_detection(); });

    #endif

    #ifdef DETECT_MINECRAFT

            register_module("c_game_instance.start_game_instance_detection", "legacy", "unknown", [this] { c_game_instance->start_game_instance_detection(); });
            register_module("c_mc_alts.start_mc_alts", "legacy", "unknown", [this] { c_mc_alts->start_mc_alts(); });

    #elif defined(DETECT_FIVEM) || defined(DETECT_SIEGE) || defined(DETECT_DAYZ) || defined(DETECT_CS)

            register_module("c_steam_alt.start_steam_alt_detection", "legacy", "unknown", [this] { c_steam_alt->start_steam_alt_detection(); });
            register_module("c_ai.scan_ai", "legacy", "unknown", [this] { c_ai->scan_ai(); });

    #elif DETECT_ROBLOX

            register_module("c_rblx.start_croblox_scan", "legacy", "unknown", [this] { c_rblx->start_croblox_scan(); }); 

    #endif

        detect.i_total_stages = static_cast<int>(modules.size());
        echo_integration::inventory = modules;
        for (const auto& module : modules) {
            futures.emplace_back(pool.enqueue([module, &completed_tasks] {
                echo_integration::run_module(module);
                // Always finish the task, including a module exception.
                try { utils->increment_progress(); } catch (...) {}
                ++completed_tasks;
            }));
        }
        size_t total_futures = futures.size ( );
        size_t stages = 12;

        for ( size_t stage = 1; stage <= stages; ++stage ) {
            size_t next_stage_threshold = ( stage == stages )
                ? total_futures
                : ( total_futures * stage ) / stages;

            while ( completed_tasks.load ( ) < next_stage_threshold ) {
                std::this_thread::sleep_for ( std::chrono::milliseconds ( 100 ) );
            }

            std::string msg = get_stage_message ( static_cast< int >( stage ) );

            detect.current_stage_index.store ( static_cast< int >( stage ) , std::memory_order_release );
            if ( scan_api ) scan_api->update_stage ( static_cast< int >( stage ) , msg );
        }

        for (auto& future : futures) future.get();
        echo_integration::correlate();
        if (!echo_integration::write_local_results())
            LOG(INFO, "N/A") << "Echo integration: local result write failed";
        integrity_heartbeat::instance ( ).stop ( );

        {
            const int upload_stage = 13;
            const std::string upload_msg = get_stage_message ( upload_stage );
            detect.current_stage_index.store ( upload_stage , std::memory_order_release );
            if ( scan_api ) scan_api->update_stage ( upload_stage , upload_msg );
        }

        Logger::instance ( ).flush_logs ( );

        std::vector<std::string> results = { xorstr_ ( "Scan completed successfully" ) };
        if ( scan_api ) scan_api->complete_scan ( results );
        else MessageBoxA ( NULL , xorstr_ ( "Error" ) , xorstr_ ( "Error In 2" ) , MB_OK );

        detect.scanned = true;
        detect.scan_started = false;
        detect.output_log = xorstr_ ("Finished." );

    }
    else
    {
        if ( !detect.self_scan_flagged )
            detect.server_offline_failure = true;
        detect.output_log = xorstr_ ( "Failed." );
    }
}
