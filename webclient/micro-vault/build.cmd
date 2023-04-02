call npm run build
rd /s /q ..\..\pkg\web\client
xcopy .\dist\ ..\..\pkg\web\client\ /d /s /v /e /y /q
