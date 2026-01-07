"""
Stripe Payment Integration for VCSO Security Assessment Platform
Handles one-time assessment payments and training subscriptions
"""

import stripe
from typing import Optional, Dict, Any
from config import config


class StripeIntegration:
    """Handle Stripe payments and subscriptions"""

    def __init__(self):
        self.api_key = config.STRIPE_SECRET_KEY
        self.publishable_key = config.STRIPE_PUBLISHABLE_KEY
        if self.api_key:
            stripe.api_key = self.api_key

    def is_configured(self) -> bool:
        """Check if Stripe is properly configured"""
        return bool(self.api_key and self.publishable_key)

    def create_customer(self, email: str, name: str = None, metadata: Dict = None) -> Optional[str]:
        """Create a Stripe customer"""
        if not self.is_configured():
            return None

        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata=metadata or {}
            )
            return customer.id
        except stripe.error.StripeError as e:
            print(f"Stripe error creating customer: {e}")
            return None

    def create_assessment_checkout_session(
        self,
        customer_id: str,
        assessment_id: str,
        success_url: str,
        cancel_url: str
    ) -> Optional[Dict[str, Any]]:
        """Create a checkout session for one-time assessment payment"""
        if not self.is_configured():
            # Return mock session for demo mode
            return {
                "id": "demo_session",
                "url": success_url + "?demo=true",
                "demo_mode": True
            }

        try:
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': config.ASSESSMENT_PRICE,
                        'product_data': {
                            'name': 'VCSO Comprehensive Security Assessment',
                            'description': 'SOC2 Self-Assessment, Vulnerability Scan, Phishing Test, Git Scan, Dark Web Scan, and Full Report',
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'assessment_id': assessment_id,
                    'type': 'assessment'
                }
            )
            return {
                "id": session.id,
                "url": session.url,
                "demo_mode": False
            }
        except stripe.error.StripeError as e:
            print(f"Stripe error creating checkout session: {e}")
            return None

    def create_subscription_checkout_session(
        self,
        customer_id: str,
        success_url: str,
        cancel_url: str
    ) -> Optional[Dict[str, Any]]:
        """Create a checkout session for monthly training subscription"""
        if not self.is_configured():
            # Return mock session for demo mode
            return {
                "id": "demo_sub_session",
                "url": success_url + "?demo=true",
                "demo_mode": True
            }

        try:
            # First, create or get the price
            price = self._get_or_create_subscription_price()

            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price.id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'type': 'training_subscription'
                }
            )
            return {
                "id": session.id,
                "url": session.url,
                "demo_mode": False
            }
        except stripe.error.StripeError as e:
            print(f"Stripe error creating subscription session: {e}")
            return None

    def _get_or_create_subscription_price(self):
        """Get or create the subscription price"""
        # Search for existing product
        products = stripe.Product.search(
            query="name:'VCSO Security Training'"
        )

        if products.data:
            product = products.data[0]
        else:
            # Create product
            product = stripe.Product.create(
                name='VCSO Security Training',
                description='Monthly security awareness training and phishing simulations'
            )

        # Get or create price
        prices = stripe.Price.list(product=product.id, active=True)
        if prices.data:
            return prices.data[0]

        return stripe.Price.create(
            product=product.id,
            unit_amount=config.TRAINING_MONTHLY_PRICE,
            currency='usd',
            recurring={'interval': 'month'}
        )

    def verify_payment(self, session_id: str) -> Dict[str, Any]:
        """Verify a payment session"""
        if not self.is_configured() or session_id == "demo_session":
            return {"status": "paid", "demo_mode": True}

        try:
            session = stripe.checkout.Session.retrieve(session_id)
            return {
                "status": session.payment_status,
                "customer_id": session.customer,
                "metadata": session.metadata,
                "demo_mode": False
            }
        except stripe.error.StripeError as e:
            print(f"Stripe error verifying payment: {e}")
            return {"status": "error", "error": str(e)}

    def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a subscription"""
        if not self.is_configured():
            return True

        try:
            stripe.Subscription.delete(subscription_id)
            return True
        except stripe.error.StripeError as e:
            print(f"Stripe error cancelling subscription: {e}")
            return False

    def get_subscription_status(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get subscription status"""
        if not self.is_configured():
            return {"status": "active", "demo_mode": True}

        try:
            sub = stripe.Subscription.retrieve(subscription_id)
            return {
                "status": sub.status,
                "current_period_end": sub.current_period_end,
                "cancel_at_period_end": sub.cancel_at_period_end,
                "demo_mode": False
            }
        except stripe.error.StripeError as e:
            print(f"Stripe error getting subscription: {e}")
            return None

    def get_price_display(self) -> Dict[str, str]:
        """Get formatted prices for display"""
        return {
            "assessment": f"${config.ASSESSMENT_PRICE / 100:.2f}",
            "training_monthly": f"${config.TRAINING_MONTHLY_PRICE / 100:.2f}/month"
        }
