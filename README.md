# Hypervision

Base dettect com integração experimental de verificações selecionadas do Echo Jean.

- [Código e notas de integração](dettect/INTEGRACAO.txt)
- [Componentes novos](dettect/detections/echo_integration/)
- [Testes](dettect/tests/)
- [Inventário de alterações](dettect/docs/alteracoes.json)
- [Pacote ZIP](output/dettect-echo-integrado.zip)

## Estado

Esta é uma integração experimental de código-fonte. Ainda existem pendências do relatório, documentadas em `dettect/INTEGRACAO.txt`. O material original contém apenas `detections/`: faltam a solução principal, `pch.h`, `utils/`, `scan_api/` e outras dependências. Não existe um executável completo validado.

Os componentes novos passaram os testes C++17/MSVC e seis testes YARA com fixtures sintéticas. O scanner completo não foi executado.

## Testes

No Windows, executar `dettect\tests\run-tests.cmd` (ajustar o caminho do Visual Studio, se necessário).

```powershell
python -m pip install yara-python
python dettect/tests/test_yara.py
```

Os novos resultados ficam localmente em `%LOCALAPPDATA%\dettect\echo-integration\latest.json`. Isto não desativa a comunicação de rede do código legado.
