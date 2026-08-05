FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY KartApiGateway.sln Directory.Build.props nuget.config ./
COPY packages/ packages/
COPY src/Api/KartApiGateway.Api.csproj src/Api/
RUN dotnet restore src/Api/KartApiGateway.Api.csproj

COPY src/ src/
RUN dotnet publish src/Api/KartApiGateway.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "KartApiGateway.Api.dll"]
