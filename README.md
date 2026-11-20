# Hypervision

Base dettect com integraÃ§Ã£o experimental de verificaÃ§Ãµes selecionadas do Echo Jean.

- [CÃ³digo e notas de integraÃ§Ã£o](INTEGRACAO.txt)
- [Componentes novos](echo_integration/)
- [Testes](tests/)
- [InventÃ¡rio de alteraÃ§Ãµes](docs/alteracoes.json)
- [Pacote ZIP](output/dettect-echo-integrado.zip)

## Estado

Esta Ã© uma integraÃ§Ã£o experimental de cÃ³digo-fonte. Ainda existem pendÃªncias do relatÃ³rio, documentadas em `INTEGRACAO.txt`. O material original contÃ©m apenas `detections/`: faltam a soluÃ§Ã£o principal, `pch.h`, `utils/`, `scan_api/` e outras dependÃªncias. NÃ£o existe um executÃ¡vel completo validado.

Os componentes novos passaram os testes C++17/MSVC e seis testes YARA com fixtures sintÃ©ticas. O scanner completo nÃ£o foi executado.

## Testes

No Windows, executar `tests\run-tests.cmd` (ajustar o caminho do Visual Studio, se necessÃ¡rio).

```powershell
python -m pip install yara-python
python tests/test_yara.py
```

Os novos resultados ficam localmente em `%LOCALAPPDATA%\dettect\echo-integration\latest.json`. Isto nÃ£o desativa a comunicaÃ§Ã£o de rede do cÃ³digo legado.
