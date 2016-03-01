import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
	        
class MailnotifikationPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'controllers')
        toolkit.add_public_directory(config_, 'public')

    def before_map(self, map):    
        map.connect('/user/register',controller='ckanext.mailNotifikation.controllers.user:CustomUserController',action='register') 
        map.connect('/answers',controller='ckanext.mailNotifikation.controllers.answer:AnswersController', action='index')
        return map
  
	


