:: %1 - $(TargetDir)
:: %2 - $(TargetName)
:: %3 - $(ProjectDir)
:: %4 - $(Configuration)

echo del /f %1%2.dll.lib
del /f "%1%2.dll.lib"

echo rename %1%2.lib %2.dll.lib
rename "%1%2.lib" "%2.dll.lib"

echo lib /NOLOGO /OUT:%1%2.lib %3\%4\*.obj
lib /NOLOGO /OUT:"%1%2.lib" "%3\%4\*.obj"