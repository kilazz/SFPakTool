using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;

namespace PakTool;

public partial class MainWindow : Window
{
    private string? _currentPakPath;
    private string? _currentFolderPath;
    private readonly ObservableCollection<FileTreeNode> _treeItems = [];

    public MainWindow()
    {
        InitializeComponent();

        var btnOpenPak = this.FindControl<Button>("BtnOpenPak");
        var btnUnpack = this.FindControl<Button>("BtnUnpack");
        var btnBatchUnpack = this.FindControl<Button>("BtnBatchUnpack");
        var btnOpenFolder = this.FindControl<Button>("BtnOpenFolder");
        var btnPack = this.FindControl<Button>("BtnPack");
        var btnBatchPack = this.FindControl<Button>("BtnBatchPack");
        var fileTree = this.FindControl<TreeView>("FileTree");
        var cmbFormat = this.FindControl<ComboBox>("CmbPackFormat");

        if (btnOpenPak != null)
        {
            btnOpenPak.Click += BtnOpenPak_Click;
        }

        if (btnUnpack != null)
        {
            btnUnpack.Click += BtnUnpack_Click;
        }

        if (btnBatchUnpack != null)
        {
            btnBatchUnpack.Click += BtnBatchUnpack_Click;
        }

        if (btnOpenFolder != null)
        {
            btnOpenFolder.Click += BtnOpenFolder_Click;
        }

        if (btnPack != null)
        {
            btnPack.Click += BtnPack_Click;
        }

        if (btnBatchPack != null)
        {
            btnBatchPack.Click += BtnBatchPack_Click;
        }

        if (fileTree != null)
        {
            fileTree.ItemsSource = _treeItems;
        }

        if (cmbFormat != null)
        {
            cmbFormat.SelectionChanged += CmbPackFormat_SelectionChanged;
            // Initialize state
            var cmbCompression = this.FindControl<ComboBox>("CmbCompressionLevel");
            if (cmbCompression != null)
            {
                cmbCompression.IsEnabled = cmbFormat.SelectedIndex != 0;
            }
        }
    }

    private void CmbPackFormat_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        var cmbFormat = this.FindControl<ComboBox>("CmbPackFormat");
        var cmbCompression = this.FindControl<ComboBox>("CmbCompressionLevel");

        if (cmbFormat != null && cmbCompression != null)
        {
            // SpellForce 1 index is 0, SpellForce 2 index is 1
            cmbCompression.IsEnabled = cmbFormat.SelectedIndex != 0;
        }
    }

    private void Log(string message)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            var txtLog = this.FindControl<TextBlock>("TxtLog");
            if (txtLog != null)
            {
                txtLog.Text = message;
            }
        });
    }

    private async void BtnOpenPak_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select .pak file to open",
            AllowMultiple = false,
            FileTypeFilter = new[] { new FilePickerFileType("SpellForce Archive") { Patterns = new[] { "*.pak" } } }
        });

        if (files.Count > 0)
        {
            _currentPakPath = files[0].Path.LocalPath;
            _currentFolderPath = null;

            var btnUnpack = this.FindControl<Button>("BtnUnpack");
            var btnPack = this.FindControl<Button>("BtnPack");
            try
            {
                var (format, entries) = await PakArchive.ReadEntriesAsync(_currentPakPath);
                BuildTreeFromEntries(entries);
                string formatName = format == PakFormat.SpellForce1 ? "SpellForce 1" : "SpellForce 2";
                Log($"Opened {_currentPakPath}. Format: {formatName}. Found {entries.Count} files.");

                if (btnUnpack != null)
                {
                    btnUnpack.IsEnabled = true;
                }

                if (btnPack != null)
                {
                    btnPack.IsEnabled = false;
                }
            }
            catch (Exception ex)
            {
                _currentPakPath = null;
                if (btnUnpack != null)
                {
                    btnUnpack.IsEnabled = false;
                }

                _treeItems.Clear();
                Log($"Error opening PAK: {ex.Message}");
            }
        }
    }

    private async void BtnUnpack_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentPakPath))
        {
            return;
        }

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select destination folder"
        });

        if (folders.Count > 0)
        {
            string outDir = folders[0].Path.LocalPath;

            var btnUnpack = this.FindControl<Button>("BtnUnpack");
            var btnOpenPak = this.FindControl<Button>("BtnOpenPak");

            if (btnUnpack != null)
            {
                btnUnpack.IsEnabled = false;
            }

            if (btnOpenPak != null)
            {
                btnOpenPak.IsEnabled = false;
            }

            try
            {
                await PakArchive.UnpackAsync(_currentPakPath, outDir, Log);
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
            finally
            {
                if (btnUnpack != null)
                {
                    btnUnpack.IsEnabled = true;
                }

                if (btnOpenPak != null)
                {
                    btnOpenPak.IsEnabled = true;
                }
            }
        }
    }

    private async void BtnBatchUnpack_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select Root Folder for Batch Unpack",
            AllowMultiple = false
        });

        if (folders.Count == 0)
        {
            return;
        }

        string rootDir = folders[0].Path.LocalPath;
        string[] pakFiles = Directory.GetFiles(rootDir, "*.pak", SearchOption.AllDirectories);

        Log($"Found {pakFiles.Length} archives. Starting batch unpack...");

        foreach (var pakPath in pakFiles)
        {
            string outDir = Path.Combine(Path.GetDirectoryName(pakPath)!, Path.GetFileNameWithoutExtension(pakPath) + "_extracted");
            Log($"Unpacking: {Path.GetFileName(pakPath)}...");
            try
            {
                await PakArchive.UnpackAsync(pakPath, outDir, (msg) => { });
            }
            catch (Exception ex)
            {
                Log($"Error unpacking {pakPath}: {ex.Message}");
            }
        }
        Log("Batch unpack finished.");
    }

    private async void BtnOpenFolder_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select folder to pack"
        });

        if (folders.Count > 0)
        {
            _currentFolderPath = folders[0].Path.LocalPath;
            _currentPakPath = null;

            var btnUnpack = this.FindControl<Button>("BtnUnpack");
            var btnPack = this.FindControl<Button>("BtnPack");
            if (btnUnpack != null)
            {
                btnUnpack.IsEnabled = false;
            }

            if (btnPack != null)
            {
                btnPack.IsEnabled = true;
            }

            try
            {
                BuildTreeFromDirectory(_currentFolderPath);
                Log($"Opened folder {_currentFolderPath}. Ready to pack.");
            }
            catch (Exception ex)
            {
                Log($"Error reading folder: {ex.Message}");
            }
        }
    }

    private async void BtnBatchPack_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select root folder containing subfolders to pack"
        });

        if (folders.Count == 0)
        {
            return;
        }

        string rootDir = folders[0].Path.LocalPath;
        var subDirs = Directory.GetDirectories(rootDir);

        if (subDirs.Length == 0)
        {
            Log("No subfolders found to pack.");
            return;
        }

        var cmbFormat = this.FindControl<ComboBox>("CmbPackFormat");
        var cmbCompression = this.FindControl<ComboBox>("CmbCompressionLevel");

        PakFormat format = cmbFormat?.SelectedIndex == 0 ? PakFormat.SpellForce1 : PakFormat.SpellForce2;
        CompressionLevel compLevel = (CompressionLevel)(cmbCompression?.SelectedIndex ?? 0);

        Log($"Starting batch pack of {subDirs.Length} folders...");

        foreach (var subDir in subDirs)
        {
            string folderName = Path.GetFileName(subDir);
            string baseName = folderName;

            // Remove _extracted suffix if present
            if (folderName.EndsWith("_extracted", StringComparison.OrdinalIgnoreCase))
            {
                baseName = folderName.Substring(0, folderName.Length - "_extracted".Length);
            }

            string outPakPath = Path.Combine(rootDir, baseName + ".pak");

            Log($"Packing {folderName} to {baseName}.pak...");
            try
            {
                await PakArchive.PackAsync(subDir, outPakPath, compLevel, format, Log);
                Log($"Successfully packed: {baseName}.pak");
            }
            catch (Exception ex)
            {
                Log($"Error packing {folderName}: {ex.Message}");
            }
        }

        Log("Batch pack complete!");
    }

    private async void BtnPack_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentFolderPath))
        {
            return;
        }

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }

        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save .pak archive",
            DefaultExtension = "pak",
            FileTypeChoices = new[] { new FilePickerFileType("SpellForce Archive") { Patterns = new[] { "*.pak" } } }
        });

        if (file != null)
        {
            string outPath = file.Path.LocalPath;

            var cmbCompression = this.FindControl<ComboBox>("CmbCompressionLevel");
            System.IO.Compression.CompressionLevel compLevel = System.IO.Compression.CompressionLevel.Optimal;
            if (cmbCompression != null)
            {
                compLevel = cmbCompression.SelectedIndex switch
                {
                    1 => System.IO.Compression.CompressionLevel.SmallestSize,
                    2 => System.IO.Compression.CompressionLevel.Fastest,
                    3 => System.IO.Compression.CompressionLevel.NoCompression,
                    _ => System.IO.Compression.CompressionLevel.Optimal
                };
            }

            var cmbFormat = this.FindControl<ComboBox>("CmbPackFormat");
            PakFormat packFormat = PakFormat.SpellForce2;
            if (cmbFormat != null && cmbFormat.SelectedIndex == 0)
            {
                packFormat = PakFormat.SpellForce1;
            }

            var btnPack = this.FindControl<Button>("BtnPack");
            var btnOpenFolder = this.FindControl<Button>("BtnOpenFolder");

            if (btnPack != null)
            {
                btnPack.IsEnabled = false;
            }

            if (btnOpenFolder != null)
            {
                btnOpenFolder.IsEnabled = false;
            }

            try
            {
                await PakArchive.PackAsync(_currentFolderPath, outPath, compLevel, packFormat, Log);
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
            finally
            {
                if (btnPack != null)
                {
                    btnPack.IsEnabled = true;
                }

                if (btnOpenFolder != null)
                {
                    btnOpenFolder.IsEnabled = true;
                }
            }
        }
    }

    private static readonly char[] PathSeparators = new[] { '\\', '/' };

    private void BuildTreeFromEntries(List<PakEntry> entries)
    {
        _treeItems.Clear();
        var rootNode = new FileTreeNode { Name = Path.GetFileName(_currentPakPath) ?? "Archive", IsDirectory = true };
        _treeItems.Add(rootNode);

        var dict = new Dictionary<string, FileTreeNode>(StringComparer.OrdinalIgnoreCase);
        dict[""] = rootNode;

        foreach (var entry in entries)
        {
            string[] parts = entry.Name.Split(PathSeparators, StringSplitOptions.RemoveEmptyEntries);
            string currentPath = "";
            FileTreeNode parent = rootNode;

            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];
                string newPath = string.IsNullOrEmpty(currentPath) ? part : currentPath + "\\" + part;

                if (!dict.TryGetValue(newPath, out var node))
                {
                    node = new FileTreeNode
                    {
                        Name = part,
                        FullPath = newPath,
                        IsDirectory = i < parts.Length - 1
                    };
                    parent.Children.Add(node);
                    dict[newPath] = node;
                }
                parent = node;
                currentPath = newPath;
            }
        }
    }

    private void BuildTreeFromDirectory(string dirPath)
    {
        _treeItems.Clear();
        var rootNode = new FileTreeNode { Name = Path.GetFileName(dirPath) ?? "Folder", IsDirectory = true, FullPath = dirPath };
        _treeItems.Add(rootNode);
        PopulateDirectoryNode(rootNode, dirPath);
    }

    private void PopulateDirectoryNode(FileTreeNode parentNode, string dirPath)
    {
        try
        {
            foreach (var dir in Directory.GetDirectories(dirPath))
            {
                var node = new FileTreeNode { Name = Path.GetFileName(dir), FullPath = dir, IsDirectory = true };
                parentNode.Children.Add(node);
                PopulateDirectoryNode(node, dir);
            }
            foreach (var file in Directory.GetFiles(dirPath))
            {
                var node = new FileTreeNode { Name = Path.GetFileName(file), FullPath = file, IsDirectory = false };
                parentNode.Children.Add(node);
            }
        }
        catch (Exception ex)
        {
            Log($"Error reading directory {dirPath}: {ex.Message}");
        }
    }
}
