# Kernel Driver Dumper

A powerful Windows kernel driver analysis and dumping tool that provides detailed information about loaded kernel modules.

## Features

- List all loaded kernel drivers with detailed information
- Display driver base addresses and sizes
- Show driver dependencies and load times
- Calculate driver hash values
- Analyze driver security status
- Export results to file
- Filter and search capabilities
- Memory usage statistics
- Signature verification
- Version information
- Configuration details

## Requirements

- Windows 10 or later
- Administrator privileges
- Visual Studio 2019 or later (for building)

## Building

1. Clone the repository
2. Open the solution in Visual Studio
3. Build the project in Release mode

## Usage

Run the executable with administrator privileges:

```cmd
DriverDumper.exe
```

### Command Line Options

- `-f, --file <path>`: Export results to specified file
- `-s, --search <name>`: Search for specific driver
- `-h, --hash`: Calculate and display driver hashes
- `-v, --verbose`: Show detailed information
- `-d, --dependencies`: Show driver dependencies
- `-t, --time`: Show load times
- `-m, --memory`: Show memory usage statistics

## Security Features

- Administrator privilege check
- Memory protection mechanisms
- Error handling and logging
- Signature verification
- Security status analysis

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

0x7ff
