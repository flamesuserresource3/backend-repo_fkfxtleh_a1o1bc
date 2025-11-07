"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

# Example schemas (replace with your own):

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product" (lowercase of class name)
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Identity & Compliance module schemas

class OtpSession(BaseModel):
    """
    OTP sessions for phone verification (MFA)
    Collection name: "otpsession"
    """
    phone: str = Field(..., description="MSISDN in international format e.g., +2250700000000")
    code: str = Field(..., min_length=4, max_length=6, description="One-time passcode")
    expires_at: datetime = Field(..., description="Expiration timestamp (UTC)")
    verified: bool = Field(False, description="Whether the OTP was verified")

class Identity(BaseModel):
    """
    Registered identities (basic KYC)
    Collection name: "identity"
    """
    phone: str = Field(..., description="MSISDN in international format e.g., +2250700000000")
    name: str = Field(..., description="Full name as per ID")
    email: EmailStr = Field(..., description="Contact email")
    country: Optional[str] = Field(None, description="ISO country code (e.g., CI, SN, BJ)")
    faith_affirmation: bool = Field(..., description="Affirms adherence to platform values")
