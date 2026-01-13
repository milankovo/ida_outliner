# IDA Outliner
![logo](logo.jpeg)

A lightweight IDA Pro plugin that adds the ability to mark functions as outlined in the decompiler view.

## Description

IDA Outliner provides a convenient way to make functions "outlined" in IDA's Hex-Rays decompiler. When a function is marked as outlined, the decompiler will collapse it to a single line, making the code more readable when dealing with large codebases.

## Features

- **Keyboard Shortcut**: Press `O` to outline the current function in either pseudocode or disassembly view
- **Context Menu Integration**: Easily toggle outlined status for functions via right-click menu
- **Works in Multiple Views**: Available in both pseudocode and disassembly windows

## Installation

### Via IDA Plugin Manager (Recommended)

1. Open IDA Pro
2. Navigate to the Plugin Manager
3. Search for "ida-outliner"
4. Click Install

### Manual Installation

1. Download the latest release from [GitHub](https://github.com/milankovo/ida_outliner)
2. Extract the plugin files to your IDA plugins directory:
   - **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - **macOS**: `~/.idapro/plugins/`
   - **Linux**: `~/.idapro/plugins/`
3. Restart IDA Pro

## Usage

1. Open a function in the decompiler (press F5)
2. Press `O` or right-click and select "Make outlined" from the context menu
3. The function will be collapsed to a single line in the decompiler view

## Requirements

- IDA Pro 9.0 or later
- Hex-Rays Decompiler

## License

MIT

## Author

Milankovo, 2025

## Links

- **Repository**: https://github.com/milankovo/ida_outliner
- **Issues**: https://github.com/milankovo/ida_outliner/issues

## See Also

- [HCLI Plugin Manager Documentation](https://hcli.docs.hex-rays.com/reference/packaging-your-existing-plugin/)
- [IDA Plugin Submission Guide](https://docs.hex-rays.com/user-guide/plugins/plugin-submission-guide)
