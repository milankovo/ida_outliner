# IDA Outliner
![logo](logo.jpeg)

A lightweight IDA Pro plugin that adds the ability to mark functions as outlined in the decompiler view.

## Description

IDA Outliner provides a convenient way to mark functions as outlined in IDA's Hex-Rays decompiler. Outlined functions are compiler-generated fragments created by function outlining optimization, which extracts common code sequences to save space. Marking them as outlined tells the decompiler to inline these fragments back into the calling functions, improving readability and eliminating undefined variable warnings.

## Features

- **Keyboard Shortcut**: Press `O` to toggle the outlined state of the current function
- **Works in Multiple Views**: Available in both pseudocode and disassembly windows
- **Automatic Inlining**: Once marked, the decompiler automatically inlines outlined functions into their callers

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

When you encounter compiler-generated outlined function fragments (often named `OUTLINED_FUNCTION_NN` or containing `.cold.` in their name):

1. Navigate to the outlined function
2. Press `O` or use the context menu action
3. The decompiler will inline the function into its callers, improving readability and eliminating undefined variable warnings

**Tip:** For binaries with many outlined functions, consider automating the process with a script that identifies and marks them based on naming patterns.

## Requirements

- IDA Pro 9.0 or later
- Hex-Rays Decompiler

## License

MIT

## Author

Milankovo, 2026

## Links

- **Repository**: https://github.com/milankovo/ida_outliner
- **Issues**: https://github.com/milankovo/ida_outliner/issues

## See Also

- [Igor's Tip of the Week #106: Outlined Functions](https://hex-rays.com/blog/igors-tip-of-the-week-106-outlined-functions)
- [HCLI Plugin Manager Documentation](https://hcli.docs.hex-rays.com/reference/packaging-your-existing-plugin/)
- [IDA Plugin Submission Guide](https://docs.hex-rays.com/user-guide/plugins/plugin-submission-guide)
