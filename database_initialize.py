import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'
	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	email = Column(String(250), nullable=False)
	picture = Column(String(250))

class Category(Base):
	__tablename__ = 'category'

	id = Column(Integer, primary_key = True)
	name = Column(String(80), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    	'id': self.id,
	        'name': self.name,
	    }

class CategoryItem(Base):
	__tablename__ = 'category_item'

	id = Column(Integer, primary_key = True)
	name = Column(String(80), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category)
	description = Column(String(250))	
	
	@property
	def serialize(self):
	    return {
	        'category': self.category.name,
	        'description': self.description,
	        'name': self.name,
	    }


engine = create_engine('postgresql://catalog:catalog123@localhost/catalog')
Base.metadata.create_all(engine)