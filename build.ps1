dotnet clean
dotnet restore -f -v m
dotnet build --no-restore --nologo -c Release 
dotnet test --no-build --nologo -v m -c Release /p:CollectCoverage=true /p:CoverletOutputFormat=opencover
dotnet clean