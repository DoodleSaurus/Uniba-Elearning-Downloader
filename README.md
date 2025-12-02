# UniBA E-Learning Downloader

## Overview
The UniBA E-Learning Downloader is a Python application designed to automate the process of downloading course materials from the UniBA E-Learning platform. It provides a user-friendly interface for students to easily access and retrieve their course files.

## Features
- Login to the UniBA E-Learning platform using your credentials.
- Automatically fetch and download course materials.
- Track downloaded files and avoid duplicates.
- Visual representation of downloaded files per course.

## Requirements
To run this application, you need to have the following Python packages installed:
- requests
- beautifulsoup4
- matplotlib
- tkinter

You can install the required packages using the following command:
```
pip install -r requirements.txt
```

## Usage
1. Clone the repository:
   ```
   git clone https://github.com/DoodleSaurus/Uniba-Elearning-Downloader.git
   cd Uniba-Elearning-Downloader
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python src/unibaElearningDownloader.py
   ```

4. Enter your UniBA credentials and organization to start downloading course materials.

## Building Executable
To create an executable version of the application, you can use the provided scripts:

- For Windows:
  ```
  scripts/build.bat
  ```

## Contributing
Contributions are welcome! If you have suggestions for improvements or find bugs, please open an issue or submit a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
