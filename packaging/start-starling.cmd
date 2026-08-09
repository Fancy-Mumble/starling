@echo off
rem Double-click this to run the server.
rem
rem starling.exe on its own prints its usage, which is right for a command line
rem and useless in a window that closes before it can be read. This starts the
rem server, and keeps the window open afterwards so that a failure is something
rem you can read rather than something you watch disappear.
title Starling
"%~dp0starling.exe" --all-in-one
echo.
echo Starling has stopped.
pause
