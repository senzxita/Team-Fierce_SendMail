from flask import abort, make_response, jsonify, request
from datetime import datetime
from markupsafe import Markup, escape
from config import db
from models import Person, PersonSchema, Users
from auth import token_required 


#init schema
person_schema = PersonSchema()
people_schema = PersonSchema(many=True)


# Create a handler for our read (GET) people
@token_required
def read_all():
    """
    This function responds to a request for /v1/people
    with the complete list of subscribers

    :return: sorted list of subscribers
    """

    # Create the list of people from our data
    people = Person.query.order_by(Person.fname).all()

    # Serialize the data for the response
    return people_schema.jsonify(people)

@token_required
def read_one(email):
    # Get the person requested
    person = Person.query.filter(Person.email == email).one_or_none()

    # Did we find a person?
    if person is not None:

        # Serialize the data for the response
        return person_schema.jsonify(person)

    # Otherwise, nope, didn't find that person
    else:
        abort(
            404, "Person with email {email} not found".format(email=email)
        )

@token_required
def create(person):
    """
    This function creates a new person in the subscribers structure
    based on the passed in person data
    :param person:  person to create in subscribers structure
    :return:        201 on success, 406 on person exist
    """
    fname = Markup.escape(person.get("fname"))
    email = Markup.escape(person.get("email"))
    if email is None or email == '' or email == 'string':
        abort(
            400, "Person's email is required"
        )
    
    create_person = Person(fname, email)
        
    existing_person = Person.query.filter(Person.email == email).one_or_none()

    # Can we insert this person?
    if existing_person is None:

        # Add the person to the database
        db.session.add(create_person)
        db.session.commit()

        # Serialize and return the newly created person in the response
        return person_schema.jsonify(create_person), 201

    # Otherwise, nope, person exists already
    else:
        abort(
            406, "Person with email {email} already exist".format(email=email)
        )

@token_required
def update(email, person):
    """
    This function updates an existing person in the people structure
    :param email:   email of person to update in the people structure
    :param person:  person to update
    :return:        updated person structure
    """
    
        # Get the person requested from the db into session
    update_person = Person.query.filter(Person.email == email).one_or_none()

    # Try to find an existing person with the same name as the update
    fname = Markup.escape(person.get("fname"))
    email = Markup.escape(person.get("email"))
    if email is None or email == '' or email == 'string':
        abort(
            400, "Person's email is required"
        )

    # Are we trying to find a person that does not exist?
    if update_person is None:
        abort(
            400, "Person with email {email} not found".format(email=email)
        )

    # Otherwise go ahead and update!
    else:

        # turn the passed in person into a db object
        update_person.fname = fname

        # merge the new object into the old and commit it to the db
        db.session.commit()

        # return updated person in the response
        data = person_schema.jsonify(person)

        return data, 200
        

@token_required
def delete(email):
    """
    This function deletes a person from the subscribers structure
    :param email:   email address of person to delete
    :return:        200 on successful delete, 404 if not found
    """
        # Get the person requested
    person = Person.query.filter(Person.email == email).one_or_none()

    # Did we find a person?
    if person is not None:
        db.session.delete(person)
        db.session.commit()
        
        return make_response(
            "Person with email {email} deleted successfully".format(email=email), 200
        )

    # Otherwise, nope, person to delete not found
    else:
        abort(
            404, "Person with email {email} not found".format(email=email)
        )

