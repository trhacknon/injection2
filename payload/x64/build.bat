@echo off
cl -nologo -Os xbin.cpp
echo.
cl -DCONSOLE -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@conhost.txt /entry:GetWindowHandle /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\conhost\payload.bin
echo.
cl -DSUBCLASS -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@propagate.txt /entry:SubclassProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\propagate\payload.bin
echo.
cl -DWINDOW -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@extrabytes.txt /entry:WndProc /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\extrabytes\payload.bin
echo.
cl -DSVCCTRL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@svcctrl.txt /entry:Handler /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\svcctrl\payload.bin
echo.
cl -DTPOOL -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c
link /order:@tpool.txt /entry:TpCallBack /base:0 payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
move payload.exe64.bin ..\..\tpool\payload.bin