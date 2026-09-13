using Npgsql;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string? port = Environment.GetEnvironmentVariable("PORT");

if (!string.IsNullOrWhiteSpace(port))
{
    app.Urls.Add($"http://0.0.0.0:{port}");
}

app.MapGet("/", () =>
{
    return Results.Ok(new
    {
        service = "Wardogs Mortar Licence API",
        status = "online"
    });
});

app.MapGet("/health", async () =>
{
    try
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        await connection.OpenAsync();

        await using var command = new NpgsqlCommand("SELECT 1;", connection);
        await command.ExecuteScalarAsync();

        return Results.Ok(new
        {
            status = "healthy",
            database = "connected"
        });
    }
    catch
    {
        return Results.Json(
            new
            {
                status = "degraded",
                database = "unavailable"
            },
            statusCode: 503
        );
    }
});

app.MapPost("/admin/create-key", async (
    HttpRequest request,
    CreateKeyRequest body) =>
{
    string? adminSecret = Environment.GetEnvironmentVariable("MORTAR_ADMIN_SECRET");
    string suppliedSecret = request.Headers["X-Admin-Key"].FirstOrDefault() ?? "";

    if (string.IsNullOrWhiteSpace(adminSecret))
    {
        return Results.Problem(
            "Server administration is not configured.",
            statusCode: 500
        );
    }

    if (!SecureEquals(adminSecret, suppliedSecret))
    {
        return Results.Unauthorized();
    }

    string username = body.Username?.Trim() ?? "";

    if (string.IsNullOrWhiteSpace(username))
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Username is required."
        });
    }

    if (username.Length > 50)
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Username is too long."
        });
    }

    await using var connection = new NpgsqlConnection(GetConnectionString());
    await connection.OpenAsync();

    for (int attempt = 0; attempt < 10; attempt++)
    {
        string licenceKey = GenerateLicenceKey();
        string keyHash = HashText(licenceKey);
        string keyHint = licenceKey[^4..];

        const string sql = """
            INSERT INTO mortar_licences
            (
                key_hash,
                key_hint,
                username
            )
            VALUES
            (
                @key_hash,
                @key_hint,
                @username
            )
            ON CONFLICT (key_hash)
            DO NOTHING
            RETURNING id;
            """;

        await using var command = new NpgsqlCommand(sql, connection);

        command.Parameters.AddWithValue("key_hash", keyHash);
        command.Parameters.AddWithValue("key_hint", keyHint);
        command.Parameters.AddWithValue("username", username);

        object? result = await command.ExecuteScalarAsync();

        if (result is long licenceId)
        {
            return Results.Ok(new
            {
                success = true,
                licenceId,
                username,
                key = licenceKey
            });
        }
    }

    return Results.Problem(
        "Could not generate a unique licence key.",
        statusCode: 500
    );
});

app.MapPost("/activate", async (ActivationRequest body) =>
{
    string licenceKey = body.Key?.Trim().ToUpperInvariant() ?? "";
    string machineHash = body.MachineHash?.Trim().ToUpperInvariant() ?? "";

    if (string.IsNullOrWhiteSpace(licenceKey))
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Activation key is required."
        });
    }

    if (!IsValidMachineHash(machineHash))
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Invalid machine fingerprint."
        });
    }

    string keyHash = HashText(licenceKey);

    await using var connection = new NpgsqlConnection(GetConnectionString());
    await connection.OpenAsync();

    await using var transaction = await connection.BeginTransactionAsync();

    const string findSql = """
        SELECT
            id,
            username,
            machine_hash,
            revoked
        FROM mortar_licences
        WHERE key_hash = @key_hash
        FOR UPDATE;
        """;

    await using var findCommand =
        new NpgsqlCommand(findSql, connection, transaction);

    findCommand.Parameters.AddWithValue("key_hash", keyHash);

    await using var reader = await findCommand.ExecuteReaderAsync();

    if (!await reader.ReadAsync())
    {
        await reader.CloseAsync();
        await transaction.RollbackAsync();

        return Results.NotFound(new
        {
            success = false,
            message = "Invalid activation key."
        });
    }

    long licenceId = reader.GetInt64(0);
    string username = reader.GetString(1);

    string? existingMachineHash =
        reader.IsDBNull(2)
            ? null
            : reader.GetString(2);

    bool revoked = reader.GetBoolean(3);

    await reader.CloseAsync();

    if (revoked)
    {
        await transaction.RollbackAsync();

        return Results.Json(
            new
            {
                success = false,
                message = "This licence has been revoked."
            },
            statusCode: 403
        );
    }

    if (existingMachineHash is null)
    {
        const string activateSql = """
            UPDATE mortar_licences
            SET
                machine_hash = @machine_hash,
                activated_at = NOW()
            WHERE id = @id;
            """;

        await using var activateCommand =
            new NpgsqlCommand(activateSql, connection, transaction);

        activateCommand.Parameters.AddWithValue("machine_hash", machineHash);
        activateCommand.Parameters.AddWithValue("id", licenceId);

        await activateCommand.ExecuteNonQueryAsync();
    }
    else if (!SecureEquals(existingMachineHash, machineHash))
    {
        await transaction.RollbackAsync();

        return Results.Conflict(new
        {
            success = false,
            message = "This activation key is already bound to another computer."
        });
    }

    await transaction.CommitAsync();

    string token = CreateLicenceToken(
        licenceId,
        username,
        machineHash
    );

    return Results.Ok(new
    {
        success = true,
        username,
        licence = token
    });
});

await EnsureDatabaseAsync();

app.Run();

async Task EnsureDatabaseAsync()
{
    string? databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL");

    if (string.IsNullOrWhiteSpace(databaseUrl))
    {
        return;
    }

    await using var connection = new NpgsqlConnection(GetConnectionString());
    await connection.OpenAsync();

    const string sql = """
        CREATE TABLE IF NOT EXISTS mortar_licences
        (
            id BIGSERIAL PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            key_hint VARCHAR(4) NOT NULL,
            username VARCHAR(50) NOT NULL,
            machine_hash CHAR(64),
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            activated_at TIMESTAMPTZ
        );
        """;

    await using var command = new NpgsqlCommand(sql, connection);
    await command.ExecuteNonQueryAsync();
}

string CreateLicenceToken(
    long licenceId,
    string username,
    string machineHash)
{
    string? privateKeyBase64 =
        Environment.GetEnvironmentVariable("LICENCE_PRIVATE_KEY");

    if (string.IsNullOrWhiteSpace(privateKeyBase64))
    {
        throw new InvalidOperationException(
            "Licence signing key is not configured."
        );
    }

    var payload = new LicencePayload(
        1,
        licenceId,
        username,
        machineHash,
        DateTimeOffset.UtcNow.ToUnixTimeSeconds()
    );

    byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload);

    using RSA rsa = RSA.Create();

    rsa.ImportPkcs8PrivateKey(
        Convert.FromBase64String(privateKeyBase64),
        out _
    );

    byte[] signature = rsa.SignData(
        payloadBytes,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1
    );

    return
        $"{Base64UrlEncode(payloadBytes)}." +
        $"{Base64UrlEncode(signature)}";
}

string GetConnectionString()
{
    string? databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL");

    if (string.IsNullOrWhiteSpace(databaseUrl))
    {
        throw new InvalidOperationException(
            "DATABASE_URL is not configured."
        );
    }

    var uri = new Uri(databaseUrl);
    string[] credentials = uri.UserInfo.Split(':', 2);

    string username =
        Uri.UnescapeDataString(credentials[0]);

    string password =
        credentials.Length > 1
            ? Uri.UnescapeDataString(credentials[1])
            : "";

    string database =
        Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));

    var connectionString = new NpgsqlConnectionStringBuilder
    {
        Host = uri.Host,
        Port = uri.Port > 0 ? uri.Port : 5432,
        Username = username,
        Password = password,
        Database = database
    };

    return connectionString.ConnectionString;
}

string GenerateLicenceKey()
{
    const string characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    string CreateSection()
    {
        Span<char> section = stackalloc char[4];

        for (int i = 0; i < section.Length; i++)
        {
            section[i] =
                characters[
                    RandomNumberGenerator.GetInt32(characters.Length)
                ];
        }

        return new string(section);
    }

    return
        $"WDOGS-{CreateSection()}-" +
        $"{CreateSection()}-" +
        $"{CreateSection()}-" +
        $"{CreateSection()}";
}

string HashText(string value)
{
    byte[] bytes =
        SHA256.HashData(
            Encoding.UTF8.GetBytes(value)
        );

    return Convert.ToHexString(bytes);
}

bool SecureEquals(string left, string right)
{
    byte[] leftHash =
        SHA256.HashData(
            Encoding.UTF8.GetBytes(left)
        );

    byte[] rightHash =
        SHA256.HashData(
            Encoding.UTF8.GetBytes(right)
        );

    return CryptographicOperations.FixedTimeEquals(
        leftHash,
        rightHash
    );
}

bool IsValidMachineHash(string value)
{
    if (value.Length != 64)
    {
        return false;
    }

    foreach (char character in value)
    {
        if (!Uri.IsHexDigit(character))
        {
            return false;
        }
    }

    return true;
}

string Base64UrlEncode(byte[] value)
{
    return Convert
        .ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}

record CreateKeyRequest(string Username);

record ActivationRequest(
    string Key,
    string MachineHash
);

record LicencePayload(
    int Version,
    long LicenceId,
    string Username,
    string MachineHash,
    long IssuedAt
);