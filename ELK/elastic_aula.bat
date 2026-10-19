@echo off
echo ===============================================
echo    LIMPEZA COMPLETA DO ELASTICSEARCH
echo ===============================================
echo.

set ES_HOME=C:\elasticsearch-9.1.3

echo Parando qualquer instância do Elasticsearch...
taskkill /f /im java.exe 2>nul

echo.
echo Limpando configurações conflitantes...

REM Fazer backup do keystore
if exist "%ES_HOME%\config\elasticsearch.keystore" (
    echo Fazendo backup do keystore...
    copy "%ES_HOME%\config\elasticsearch.keystore" "%ES_HOME%\config\elasticsearch.keystore.backup" >nul
    del "%ES_HOME%\config\elasticsearch.keystore"
    echo Keystore removido!
)

REM Remover certificados se existirem
if exist "%ES_HOME%\config\certs" (
    echo Removendo certificados SSL...
    rmdir /s /q "%ES_HOME%\config\certs"
    echo Certificados removidos!
)

REM Limpar dados antigos (descomente se quiser reset completo dos dados)
REM if exist "%ES_HOME%\data" (
REM     echo Limpando dados antigos...
REM     rmdir /s /q "%ES_HOME%\data"
REM     echo Dados removidos!
REM )

REM Limpar logs antigos
if exist "%ES_HOME%\logs" (
    echo Limpando logs antigos...
    del /q "%ES_HOME%\logs\*.log" 2>nul
    echo Logs limpos!
)

echo.
echo ===============================================
echo    LIMPEZA CONCLUÍDA!
echo ===============================================
echo.
echo Agora execute: start-elasticsearch-aula.bat
echo.
pause