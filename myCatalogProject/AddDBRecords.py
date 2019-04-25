from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from databaseSetup import Category, Item, Base, User

#Database set up
engine = create_engine('sqlite:///catalogProject.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
# Add Inital User
User1 = User(name="Me MySelf", email="mgatliff@gmail.com")
session.add(User1)
session.commit()

#Set up the intial categories array categories 
categories = ["Mexican", "AsianFusion", "Southern", "Deli"]
Mexican =[
	["Willy's Mexicana Grill", 
	"Colorful taqueria chain serves up made-to-order burritos alongside other casual Mexican favorites."],
	["Tin Lizzy's Cantina",
	"Tacos, margarita pitchers & live music entertain a vibrant crowd in a laid-back cantina with patio."]
]

AsianFusion =[
	["Noodle", 
	"Noodles & dishes from all around Asia plus cocktails in a stylish space lit by chandeliers."],
	["Takorea",
	"Lively taqueria with a year-round porch, mixing Mexican & Korean street eats, plus signature drinks."]
]

Southern =[
	["The Lawrence", 
	"Stylish setting for contemporary Southern fare, inventive cocktails & a signature house bourbon."],
	["Simon's Restaurant",
	"Southern cuisine with global flavors, from Spain to Japan, in a contemporary, multilevel space."]
]

Deli =[
	["Jason's Deli", 
	"Deli chain featuring piled-high sandwiches, a salad bar & health-conscious fare."],
	["Newk's Eatery",
	"Regional chain offering a menu of salads, pizzas & sandwiches in a casual setting."]
]
''' Loop thur the categories array to set the resaurantArray value, 
then loop thur the restaurantArray to add the default records. 
'''
i = 0
while i < len(categories):
	category = Category(user_id=1, name= categories[i] )
	print(categories[i])
	session.add(category)
	session.commit()
	if categories[i] == "Mexican":
		restaurantArray=Mexican
	elif categories[i] == "AsianFusion":
		restaurantArray=AsianFusion
	elif categories[i] == "Southern":
		restaurantArray=Southern
	elif categories[i] == "Deli":
		restaurantArray=Deli
	else:
		restaurantArray=[["Unknown","No Restaurants are defined for this category"]]
	restaurants = restaurantArray
	for restaurant in restaurants:
		print(restaurant[0])
		print(restaurant[1])
		addRestaurant = Item(user_id=1, name=restaurant[0], description=restaurant[1],category=category)
		session.add(addRestaurant)
		session.commit()
	i += 1


