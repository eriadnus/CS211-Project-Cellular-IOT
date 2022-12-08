# To setup testbed environment:

0. Setup Python virtual environment: https://docs.python.org/3/library/venv.html

1. Install MobileInsight:

```
cd mobileinsight-core
./install-ubuntu.sh
(or ./install-macos.sh)

# you can also run the follwoing command after the compilation above to install the MobileInsight to the sudo user with 
sudo python3 setup.py install

# After that, run the example analyzer in the example folder to test the installation
```

2. Install atinout via fresh clone/source code found online at https://atinout.sourceforge.net/download.html.
    - Removed `-Werror` in downloaded `Makefile` due to failing error on build.
    - Now, atinout should complete: `echo AT | sudo atinout - /dev/ttyUSB2 -` --> "\nOK"

3. Install `pyserial` for use by the Python script suite:

```
sudo pip install pyserial
```

# To start data collection:

1. Setup testbed for data collection:

```
# Init the modem setting
echo 'AT+CFUN=1,0' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CREG=2' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CGREG=2' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CEREG=2' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CMEE=2' | sudo atinout - /dev/ttyUSB2 -
# Select the operator
echo 'AT+COPS=1,2,"310260"' | sudo atinout - /dev/ttyUSB2 -
# Perform
echo 'AT+CGATT=1' | sudo atinout - /dev/ttyUSB2 -
# Check registration status, if returns AT+CREG:2,5,xxxx, the 5 indicate the board is connected and under roaming status, which indicates the connection is successfully setup
echo 'AT+CREG?' | sudo atinout - /dev/ttyUSB2 -

# To send the ping traffic, register first
echo 'AT+COPS=1,2,"310260"' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CGATT=1' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CREG?' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CGACT=1,1' | sudo atinout - /dev/ttyUSB2 -
echo 'AT+CGDCONT?' | sudo atinout - /dev/ttyUSB2 -
echo 'AT#SGACT=1,1' | sudo atinout - /dev/ttyUSB2 -
echo 'AT#PING=8.8.8.8,1' | sudo atinout - /dev/ttyUSB2 -
```

2. Run Python scripts for configuring device, generate ping traffic, and record/log messages. These scripts are invoked as follows:

```
# open another terminal, run the following scripts for log collection
sudo python3 write_cfg_file.py /dev/ttyUSB0 115200 default.cfg
sudo python3 catch_all_log.py /dev/ttyUSB0 115200 test.qmdl

# open another terminal, run the following scripts to generate ping traffic
# NOTE: the atinout may need to be copied to the /usr/bin
sudo python3 collect_atinout.py
# if the atinout scripts could receive the ping results, then the board is connected
```

3. Move (as desired) to generate interesting data!

# To stop data collection:

1. Terminate `catch_all_log.py` script to nominally close log file.

2. Close terminal running `collect_atinout.py` script to stop ping traffic generation.

3. Disconnect the CIoT module's USB connection.
