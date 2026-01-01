using System.Text.Json;

namespace BaseScanner.Services;

/// <summary>
/// Service for creating and managing file backups for transformation rollback.
/// </summary>
public class BackupService
{
    private readonly string _backupRoot;
    private const string BackupMetadataFile = "backup.json";

    public BackupService(string? projectPath = null)
    {
        // Store backups in .basescanner/backups relative to project or user profile
        var baseDir = projectPath ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _backupRoot = Path.Combine(baseDir, ".basescanner", "backups");
        Directory.CreateDirectory(_backupRoot);
    }

    /// <summary>
    /// Create a backup of the specified files.
    /// </summary>
    /// <returns>The backup ID for later restoration.</returns>
    public async Task<string> CreateBackupAsync(List<string> filePaths)
    {
        var backupId = GenerateBackupId();
        var backupDir = Path.Combine(_backupRoot, backupId);
        Directory.CreateDirectory(backupDir);

        var fileBackups = new List<FileBackupEntry>();

        foreach (var filePath in filePaths)
        {
            if (!File.Exists(filePath))
                continue;

            var relativePath = GetRelativePath(filePath);
            var backupFilePath = Path.Combine(backupDir, SanitizePathForBackup(relativePath));

            // Ensure directory exists
            var backupFileDir = Path.GetDirectoryName(backupFilePath);
            if (backupFileDir != null)
                Directory.CreateDirectory(backupFileDir);

            // Copy file content
            var content = await File.ReadAllTextAsync(filePath);
            await File.WriteAllTextAsync(backupFilePath, content);

            fileBackups.Add(new FileBackupEntry
            {
                OriginalPath = filePath,
                BackupPath = backupFilePath,
                FileHash = ComputeHash(content)
            });
        }

        // Save metadata
        var metadata = new BackupMetadata
        {
            Id = backupId,
            CreatedAt = DateTime.UtcNow,
            Files = fileBackups,
            Description = $"Backup of {fileBackups.Count} files"
        };

        var metadataPath = Path.Combine(backupDir, BackupMetadataFile);
        var json = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(metadataPath, json);

        return backupId;
    }

    /// <summary>
    /// Restore files from a backup.
    /// </summary>
    public async Task<bool> RestoreBackupAsync(string backupId)
    {
        var backupDir = Path.Combine(_backupRoot, backupId);
        var metadataPath = Path.Combine(backupDir, BackupMetadataFile);

        if (!File.Exists(metadataPath))
            return false;

        var json = await File.ReadAllTextAsync(metadataPath);
        var metadata = JsonSerializer.Deserialize<BackupMetadata>(json);

        if (metadata == null)
            return false;

        foreach (var entry in metadata.Files)
        {
            if (!File.Exists(entry.BackupPath))
                continue;

            var content = await File.ReadAllTextAsync(entry.BackupPath);
            await File.WriteAllTextAsync(entry.OriginalPath, content);
        }

        return true;
    }

    /// <summary>
    /// List all available backups.
    /// </summary>
    public async Task<List<BackupInfo>> ListBackupsAsync()
    {
        var backups = new List<BackupInfo>();

        if (!Directory.Exists(_backupRoot))
            return backups;

        foreach (var backupDir in Directory.GetDirectories(_backupRoot))
        {
            var metadataPath = Path.Combine(backupDir, BackupMetadataFile);
            if (!File.Exists(metadataPath))
                continue;

            try
            {
                var json = await File.ReadAllTextAsync(metadataPath);
                var metadata = JsonSerializer.Deserialize<BackupMetadata>(json);

                if (metadata != null)
                {
                    backups.Add(new BackupInfo
                    {
                        Id = metadata.Id,
                        CreatedAt = metadata.CreatedAt,
                        FileCount = metadata.Files.Count,
                        Description = metadata.Description
                    });
                }
            }
            catch
            {
                // Skip corrupted backup metadata
            }
        }

        return backups.OrderByDescending(b => b.CreatedAt).ToList();
    }

    /// <summary>
    /// Delete a specific backup.
    /// </summary>
    public Task<bool> DeleteBackupAsync(string backupId)
    {
        var backupDir = Path.Combine(_backupRoot, backupId);

        if (!Directory.Exists(backupDir))
            return Task.FromResult(false);

        try
        {
            Directory.Delete(backupDir, recursive: true);
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Clean up backups older than the specified age.
    /// </summary>
    public async Task CleanupOldBackupsAsync(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        var backups = await ListBackupsAsync();

        foreach (var backup in backups.Where(b => b.CreatedAt < cutoff))
        {
            await DeleteBackupAsync(backup.Id);
        }
    }

    /// <summary>
    /// Get detailed information about a specific backup.
    /// </summary>
    public async Task<BackupDetails?> GetBackupDetailsAsync(string backupId)
    {
        var backupDir = Path.Combine(_backupRoot, backupId);
        var metadataPath = Path.Combine(backupDir, BackupMetadataFile);

        if (!File.Exists(metadataPath))
            return null;

        var json = await File.ReadAllTextAsync(metadataPath);
        var metadata = JsonSerializer.Deserialize<BackupMetadata>(json);

        if (metadata == null)
            return null;

        var files = new List<BackupFileInfo>();
        foreach (var entry in metadata.Files)
        {
            var info = new FileInfo(entry.BackupPath);
            files.Add(new BackupFileInfo
            {
                OriginalPath = entry.OriginalPath,
                Size = info.Exists ? info.Length : 0,
                Hash = entry.FileHash
            });
        }

        return new BackupDetails
        {
            Id = metadata.Id,
            CreatedAt = metadata.CreatedAt,
            Description = metadata.Description,
            Files = files,
            TotalSize = files.Sum(f => f.Size)
        };
    }

    /// <summary>
    /// Verify backup integrity by checking file hashes.
    /// </summary>
    public async Task<BackupVerificationResult> VerifyBackupAsync(string backupId)
    {
        var backupDir = Path.Combine(_backupRoot, backupId);
        var metadataPath = Path.Combine(backupDir, BackupMetadataFile);

        if (!File.Exists(metadataPath))
        {
            return new BackupVerificationResult
            {
                IsValid = false,
                ErrorMessage = "Backup not found"
            };
        }

        var json = await File.ReadAllTextAsync(metadataPath);
        var metadata = JsonSerializer.Deserialize<BackupMetadata>(json);

        if (metadata == null)
        {
            return new BackupVerificationResult
            {
                IsValid = false,
                ErrorMessage = "Invalid backup metadata"
            };
        }

        var errors = new List<string>();

        foreach (var entry in metadata.Files)
        {
            if (!File.Exists(entry.BackupPath))
            {
                errors.Add($"Missing backup file: {entry.OriginalPath}");
                continue;
            }

            var content = await File.ReadAllTextAsync(entry.BackupPath);
            var currentHash = ComputeHash(content);

            if (currentHash != entry.FileHash)
            {
                errors.Add($"Hash mismatch for: {entry.OriginalPath}");
            }
        }

        return new BackupVerificationResult
        {
            IsValid = errors.Count == 0,
            Errors = errors
        };
    }

    private string GenerateBackupId()
    {
        return $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8]}";
    }

    private string GetRelativePath(string fullPath)
    {
        // Create a safe relative path for backup storage
        var drive = Path.GetPathRoot(fullPath) ?? "";
        return fullPath.Substring(drive.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private string SanitizePathForBackup(string path)
    {
        // Replace invalid characters with underscores
        return path.Replace(":", "_").Replace("\\\\", "_");
    }

    private string ComputeHash(string content)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }
}

/// <summary>
/// Backup information for listing.
/// </summary>
public record BackupInfo
{
    public required string Id { get; init; }
    public required DateTime CreatedAt { get; init; }
    public required int FileCount { get; init; }
    public string? Description { get; init; }
}

/// <summary>
/// Detailed backup information.
/// </summary>
public record BackupDetails
{
    public required string Id { get; init; }
    public required DateTime CreatedAt { get; init; }
    public string? Description { get; init; }
    public List<BackupFileInfo> Files { get; init; } = [];
    public long TotalSize { get; init; }
}

/// <summary>
/// Information about a backed up file.
/// </summary>
public record BackupFileInfo
{
    public required string OriginalPath { get; init; }
    public required long Size { get; init; }
    public required string Hash { get; init; }
}

/// <summary>
/// Result of backup verification.
/// </summary>
public record BackupVerificationResult
{
    public required bool IsValid { get; init; }
    public string? ErrorMessage { get; init; }
    public List<string> Errors { get; init; } = [];
}

// Internal classes for serialization
internal record BackupMetadata
{
    public required string Id { get; init; }
    public required DateTime CreatedAt { get; init; }
    public required List<FileBackupEntry> Files { get; init; }
    public string? Description { get; init; }
}

internal record FileBackupEntry
{
    public required string OriginalPath { get; init; }
    public required string BackupPath { get; init; }
    public required string FileHash { get; init; }
}
