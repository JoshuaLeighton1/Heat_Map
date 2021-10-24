import urllib.request, urllib.parse, urllib.error
import requests
import pandas as pd 
import dask.dataframe as dd

from bs4 import BeautifulSoup
#create data module, i might make this into a class though, and make use of inheritance to call functions within this
#this function takes in a country name and then will output the data associated with it
class getData:

    def __init__(self, x):
        self.x = x

    def scrape(self):

        #create a get request for the page im scraping
        #page = requests.get("https://www.worldometers.info/coronavirus")
        #use beautifulsoup to parse through the content
        soup = BeautifulSoup(self.x.content,'html.parser')
        #finding the code within the website for the table and the data therein 
        table_data = soup.find('table', attrs = {'id':'main_table_countries_today'})
        #this is a continuation to find the data within the rows
        rows = table_data.find_all("tr", attrs = {"style": ""})
        #create an empty list to store the data
        data = []
        datadict = {}
        cont_dict = {}
        all_dict= {}
        #enumerate the rows 
        for i,item in enumerate(rows):
            if i == 0:
                data.append(item.text.strip().split("\n")[:13])

            else:
                data.append(item.text.strip().split("\n")[:12])
        #assign key value pairs to a dictionary in order to search the data for specifics about a country
        africa = ["South Africa", "Morocco", "Tunisia", "Ethiopia", "Libya", "Egypt", "Kenya", "Zamiba",
            "Nigeria", "Algeria", "Botswana", "Mozambique", "Zimbabwe", "Ghana", "Namibia", "Uganda", "Rwanda", "Cameroon", "Senegal", "Malawi", "Angola", "Ivory Coast", "DRC", "Réunion",
            "Eswatini", "Madagascar", "Sudan", "Cabo Verde", "Mauritania", "Gabon", "Guinea", "Tanzania", "Togo", "Benin", "Seychelles", "Lesotho", "Somalia", "Mayotte", "Burundi", "Mauritius", "Mali", "Congo", "Burkina Faso", "Djibouti", "Equatorial Guinea", "South Sudan", "CAR", "Gambia", "Eritrea", "Sierra Leone", "Guinea-Bissau", "Niger", "Libera", "Chad", "Comoros",
            "Sao Tome and Principe", "Western Sahara", "Saint Helena"]
        europe = ["UK", "Russia", "France", "Spain", "Italy", "Germany"
         ,"Poland", "Ukraine", "Netherlands", "Czechia", "Romania", "Belgium", "Sweden",
        "Portugal", "Serbia", "Switzerland", "Hungary", "Austria", "Greece", "Belarus",
        "Bulgaria", "Slovakia", "Croatia", "Ireland", "Denmark", "Lithuania", "Moldova",
        "Slovenia", "Bosnia and Herzegovina", "North Macedonia", "Norway", "Albania", "Latvia",
        "Estonia", "Finland", "Montenegro","Luxembourg", "Malta", "Andorra", "Iceland", "Channel islands",
        "Isle of Man", "Girbaltar", "San Marino", "Liechtenstein", "Monaco", "Faeroe Islands", "Vatican City"
        ]
        oceana = ["Australia", "Fiji", "French Polynesia", "Papua New Guinea", "New Caledonia",
        "New Zealand", "Wallis and Futuna", "Solomon Islands", "Palau", "Vanuatu", "Marshall Islands", "Somoa", "Micronesia"]
        south_america = ["Brazil", "Argentina", "Colombia", "Peru", "Chile", "Ecuador","Bolivia", "Paraguay", "Uruguay", "Venezuela", "Suriname", "French Guiana", "Guyana", "Falkland Islands"]
        asia = ["India", "Turkey", "Iran", "Indonesia", "Philippines", "Malaysia", "Iraq", "Thailand", "Japan", "Bangladesh", "Israel", "Pakistan", "Kazakhstan", "Vietnam", "Jordan", "Nepal", "UAE", "Georgia", "Lebanon", "Saudi Arabia", "Sri Lanka", "Azerbaijan", "Myanmar", "Palestine", "Kuwait", "S. Korea", "Mongolia",
         "Oman", "Bahrain", "Armenia", "Qatar", "Kyrgyzstan", "Uzbekistan", "Afghanistan", "Singapore", "Cyprus", "Cambodia", "China", "Maldives", "Syria", "Laos",
        "Timor-Leste", "Tajikistan", "Taiwan", "Hong Kong", "Yemen", "Brunei", "Bhutan", "Macao"]
        north_america = ["USA", "Mexico", "Canada", "Cuba", "Guatemala", "Costa Rica", "Panama", "Honduras", "Dominican Republic", "El Salvador", "Jamaica", "Guadeloupe", "Trinidad and Tobago", "Martinique", "Haiti", "Belize", "Bahamas", "Curaçao", "Aruba", "Nicaragua", "Saint Lucia",
        "Barbados", "Grenada", "Bermuda", "Sint Maarten", "Dominica", "St. Vincent Grenadines", "Saint Martin", "Antigua and Barbuda","Turks and Caicos",
        "British Virgin Islands", "Saint Kitts and Nevis", "Caribbean Netherlands", "St. Barth", "Cayman Islands", "Greenland", "Anguilla",
        "Montserrat", "Saint Pierre Miquelon"]
        continents = [africa, asia, south_america, north_america, oceana, europe]
        continentsl = ["Africa", "Asia", "South_america", "North_america", "Oceana", "Europe"]
        for i in range(2, len(data)-1):
            for j in range(len(continents)):
                for k in continents[j]:
                    if data[i][1] in k:
                        if continentsl[j] not in cont_dict:
                            cont_dict[continentsl[j]] = [data[i][1]]
                        else: 
                            cont_dict[continentsl[j]].append(data[i][1])
                    datadict[data[i][1]] = i-1

        #use pandas to create a dataframe
        dt = pd.DataFrame(data)
        dt = pd.DataFrame(data[1:], columns=data[0][:12])
        df = dd.from_pandas(dt,npartitions = 1)

        count = 0

        for key in datadict: 
            all_dict[key] = dt.loc[datadict[key]]

        return datadict, cont_dict, dt, all_dict

    def get_continent(self, inp, x, y, z):
        for key in x:
            if inp == key:
                for i in x[inp]:
                    test = (z.loc[y[i]])
                    print(test)

    def get_country(self, x,y,z):
        print(z.loc[y[x]])

    def get_all(self, z,y):
        for key in z:
            country = y.loc[z[key]]
            for index, value in country.items():
                return(f"{index} Value: {value}")
            

 #output = df.to_csv("C:/Users/lucyr/Downloads/HeatMap/data-*.csv")