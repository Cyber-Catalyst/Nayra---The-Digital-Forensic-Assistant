from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email
import bleach

# Switches for enabling/disabling login and signup functionalities
MODULE_SWITCH_LOGIN = 1  # 1 means enabled, 0 means disabled
MODULE_SWITCH_SIGNUP = 1  # 1 means enabled, 0 means disabled

class LoginForm(FlaskForm):
    # Check if the switch for login functionality is disabled
    if MODULE_SWITCH_LOGIN == 0:
        name = StringField('Login functionality is disabled.')
        password = PasswordField('Login functionality is disabled.')
        role = SelectField('Login functionality is disabled.', choices=[])
        submit = SubmitField('Login functionality is disabled.')
    else:
        # Only initialize form fields if the switch is on (enabled)
        name = StringField('Username', 
                           validators=[DataRequired()],
                           filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
        password = PasswordField('Password', validators=[DataRequired()])
        role = SelectField('Role', 
                           choices=[('admin', 'Admin'), 
                                    ('super_admin', 'Super Admin'), 
                                    ('user', 'User')],
                           validators=[DataRequired()])
        
        submit = SubmitField('Login')

class SignupForm(FlaskForm):
    # Check if the switch for signup functionality is disabled
    if MODULE_SWITCH_SIGNUP == 0:
        name = StringField('Signup functionality is disabled.')
        email = StringField('Signup functionality is disabled.')
        password = PasswordField('Signup functionality is disabled.')
        submit = SubmitField('Signup functionality is disabled.')
    else:
        # Only initialize form fields if the switch is on (enabled)
        name = StringField('Name', 
                           validators=[DataRequired()],
                           filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
        email = StringField('Email', 
                            validators=[DataRequired(), Email()],
                            filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Signup')
