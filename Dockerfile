FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

COPY ["Mortar Licence API.Server.csproj", "./"]

RUN dotnet restore "Mortar Licence API.Server.csproj"

COPY . .

RUN dotnet publish "Mortar Licence API.Server.csproj" \
    -c Release \
    -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final

WORKDIR /app

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Mortar Licence API.Server.dll"]
