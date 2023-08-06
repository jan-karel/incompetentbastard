import os
import webkit
from flask import Flask



class WebViewFlask(Flask):
    """
    Adds the ability to load a uri without the
    need of a HTTP server.
    """
    def load_from_uri(self, uri):
        """
        Loads a uri without a running HTTP server.
        """
        with self.test_client() as c:
            response = c.get(uri)
            return response.data, response.mimetype


class FlaskAppView(webkit.WebView):
    """
    Loads pages for flask apps into a WebView.
    """
    def __init__(self, flask_app, *args, **kwargs):
        # Protocol for flask app, by default file:// is used
        # so a protocol is defined here to prevent that.
        self.PROTOCOL = 'flask://' 

        super(webkit.WebView, self).__init__(*args, **kwargs)

        self._flask_app = flask_app

        # Register new navigation handler.
        self.connect(
            "navigation-policy-decision-requested",
            self._nav_request
        )

        # For navigation handler.
        self.prev_uri = None

        # Redefine open like this as when using super
        # an error like this occurs:
        #   AttributeError: 'super' object has no attribute 'open'
        self._open = self.open
        self.open = self.open_

    def _nav_request(self, view, frame, net_req, nav_act, pol_dec):
        """
        WebView navigation handler for Flask apps.
        """
        # Get the uri
        uri = net_req.get_uri()

        # In order for flask apps to use relative links
        # the protocol is removed and it is made into an absolute
        # path.
        if uri.startswith(self.PROTOCOL):
            # In this case it is not relative but
            # it needs to have it's protocol removed
            uri = uri[len(self.PROTOCOL):]

        elif not self.prev_uri.endswith(uri):
            # It is relative and self.prev_uri needs to
            # be appended.
            uri = os.path.normpath(os.path.join(self.prev_uri, uri))

        # This is used to prevent an infinite recursive loop due
        # to view.load_string running this function with the same
        # input.
        if uri == self.prev_uri:
            return False

        self.prev_uri = uri

        # Create response from Flask app.
        response = app.load_from_uri(uri) + ('utf-8', uri)

        # Load response.
        view.load_string(*response)

        # Return False to prevent additional
        # handlers from running.
        return False

    def open_(self, uri):
        """
        Prepends protocol to uri for webkit.WebView.open.
        """
        self._open(self.PROTOCOL + uri)




