@echo off
REM Inicia o Elasticsearch para a aula (cluster "elasticsearch-aula").
REM Referenciado por elastic_aula.bat (limpeza). Ajuste ES_HOME se necessário.

set ES_HOME=C:\elasticsearch-9.1.3

echo ===============================================
echo    INICIANDO ELASTICSEARCH (aula)
echo ===============================================
echo.
echo ES_HOME: %ES_HOME%
echo Config:  %ES_HOME%\config\elasticsearch.yml
echo.
echo Antes do primeiro uso, copie a config da aula:
echo   copy "%~dp0elastisearch.yml" "%ES_HOME%\config\elasticsearch.yml"
echo.
echo Apos iniciar, teste em: http://localhost:9200
echo (Ctrl+C para parar)
echo.

if not exist "%ES_HOME%\bin\elasticsearch.bat" (
  echo [ERRO] Nao encontrei "%ES_HOME%\bin\elasticsearch.bat"
  echo Ajuste a variavel ES_HOME no topo deste script.
  pause
  exit /b 1
)

cd /d "%ES_HOME%"
call bin\elasticsearch.bat
