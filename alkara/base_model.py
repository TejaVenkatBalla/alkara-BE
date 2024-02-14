"""
    This module for BaseModel.
"""
from django.db import models
from datetime import datetime


class BaseModel(models.Model):
    """
    Base model
    Attributes:
        created_at (datetime): Date and time of create
        updated_at (datetime): Date and time of update
        is_delete (bool): is the record is deleted
    """
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    deleted_at = models.DateTimeField(default=None,null=True)


    class Meta:
        """
        The Meta class allows customization and configuration of various aspects of the model.
        It is used to define metadata and specify additional options that control the behavior
        of the model in Django.
        """
        abstract = True

    def update(self, **kwargs):
        """
        The update method allows updating multiple instances of the model in the database
        in a single query, providing a more efficient way to perform bulk updates.
        """
        for field, value in kwargs.items():
            setattr(self, field, value)
        self.save()

    def inactivate(self):
        self.deleted_at = datetime.now()
        self.save()

    def activate(self):
        self.deleted_at= None
        self.save()