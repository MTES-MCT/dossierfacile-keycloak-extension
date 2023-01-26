package org.keycloak.dossierfacile;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.util.LinkedList;
import java.util.List;

public class DossierFacileEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(DossierFacileEventListenerProvider.class);
    private static final String API_TENANT_API_KEY = "KC_API_TENANT_API_KEY";
    private static final String API_TENANT_KC_EVENT_URL = "KC_API_TENANT_KC_EVENT_URL";
    private final KeycloakSession session;

    public DossierFacileEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {

        log.infof("######### READ EVENT %s", event.getType());

        if (EventType.REGISTER.equals(event.getType())) {
            try {
                log.infof("API_TENANT_API_KEY=", System.getenv(API_TENANT_API_KEY));
                log.infof("API_TENANT_KC_EVENT_URL=", System.getenv(API_TENANT_KC_EVENT_URL));

                HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
                HttpPost post = new HttpPost(System.getenv(API_TENANT_KC_EVENT_URL));
                post.addHeader("X-API-Key", System.getenv(API_TENANT_API_KEY));

                List<NameValuePair> params = new LinkedList<>();
                params.add(new BasicNameValuePair("event", JsonSerialization.writeValueAsString(event)));

                UrlEncodedFormEntity form = new UrlEncodedFormEntity(params, "UTF-8");
                post.setEntity(form);
                HttpResponse response = httpClient.execute(post);
                log.info("Status=" + response.getStatusLine());

            } catch (Exception e) {
                log.error("Unable to notify api", e);
            }

        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {

    }

    @Override
    public void close() {

    }
}
