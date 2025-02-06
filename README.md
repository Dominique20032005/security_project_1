#Open the project in the terminal and enable the env with:
env\Scripts\activate
#Run the app with the command:
python firewall_manager.py

#If error try install:
pip install pyinstaller
pip install PyQt5
#Then build with the command:
pyinstaller --onefile --noconsole --uac-admin --icon=wall.ico --add-data "firewall_manager.manifest;." firewall_manager.py
#If error occure when building the app turn of the firewall and try again 
