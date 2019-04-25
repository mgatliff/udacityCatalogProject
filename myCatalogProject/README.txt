MyCatalogProject: Simple python web project to list categories of restuarants. 

Setup:
1) Download or fork from Github : https://github.com/udacity/fullstack-nanodegree-vm
2) Go to the vagrant directory in the command line and bring up the VM (vagrant up)
3) SSh into the VM instance (vagrant ssh)

project execution:
1) navigate to the project folder (/vagrant/myCatalogProject)
2) run databaseSetup.py (python databaseSetup.py), to set up the database tables. 
3) run AddDBRecords.py (python AddDBRecords.py), to add inital set of restuarants to the database.
	The consol will show the records that have been added. 
4) open a web browser and navigate to http://localhost:8080/
5) JSON output: 
	http://localhost:8080/category/JSON - JSON representation of all catagories
	http://localhost:8080/category/2/item/JSON - JSON representation of all items for catagory 2
	http://localhost:8080/users/JSON - JSON representation for all existing users 
	
