from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField, DateField, ValidationError
from wtforms.validators import DataRequired, Length

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[
        ('Low', 'Low'), 
        ('Medium', 'Medium'), 
        ('High', 'High')
    ], validators=[DataRequired()])
    status = SelectField('Status', choices=[
        ('To Do', 'To Do'),
        ('In Progress', 'In Progress'),
        ('Done', 'Done')
    ], validators=[DataRequired()])
    submit = SubmitField('Save Task')

def validate_due_date(self, due_date):
    if self.start_date.data and due_date.data < self.start_date.data:
        raise ValidationError('Due date cannot be before start date.')