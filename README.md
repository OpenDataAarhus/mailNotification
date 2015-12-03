When a user register an account in CKAN, the user will first resive a activation mail, with a link to activate the account.

Setup
-----------------
create database odaa_default;

CREATE TABLE mailNotifikation (_guid VARCHAR PRIMARY KEY UNIQUE NOT NULL, _date date, name VARCHAR, fullname VARCHAR, email VARCHAR, password VARCHAR,registered BOOLEAN);

grant insert on mailnotifikation to ckan_default;
grant update on mailnotifikation to ckan_default;
grant select on mailnotifikation to ckan_default;
grant delete on mailnotifikation to ckan_default;

Add this to CKAN configuration file.
ckan.plugins = ... mailNotifikation

dk.aarhuskommune.odaa_url = postgresql://ckan_default:pass@localhost/odaa_default
	Replace pass with the password, you created than you create the user ckan_default.
	
dk.aarhuskommune.odaa_days = 30 (Days before the records in table mailNotifikation will be delete.)
dk.aarhuskommune.odaa_from = from@email.com (From email.)

