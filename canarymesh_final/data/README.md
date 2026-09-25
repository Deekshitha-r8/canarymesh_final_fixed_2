# ToN-IoT data directory

CanaryMesh expects the UNSW ToN-IoT IoT/IIoT CSV files in this directory.

The backend downloads missing files automatically from the configured mirror. The default mirror is:

`https://raw.githubusercontent.com/PengaloGit/ToN_IoT-datasets/main/Train_Test_IoT_dataset`

The authoritative project page is the UNSW ToN-IoT dataset page:
`https://research.unsw.edu.au/projects/toniot-datasets`

Default files:

- `Train_Test_IoT_Modbus.csv`
- `Train_Test_IoT_Weather.csv`
- `Train_Test_IoT_Garage_Door.csv`
- `Train_Test_IoT_Thermostat.csv`

Optional supported files:

- `Train_Test_IoT_Fridge.csv`
- `Train_Test_IoT_Motion_Light.csv`
- `Train_Test_IoT_GPS_Tracker.csv`

Do not commit the raw benchmark files to the application repository unless your competition/licensing policy permits it. The application can acquire them at startup and import them into its local SQLite database.
