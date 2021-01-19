# rest-api-oauth-example

An oAuth example using PHP to authenticate incoming WooCommerce webhooks. This is part of the code from a REST API integration I made between WooCommerce and a multi-channel sales service.

The webhook header source is used to query a database to obtain the correct secret key for that source. The secret key returned by this query can then be encoded and compared to the incoming webhook signature value to authenticate the transaction.

The x-wc-webhook-source value can be used to query the database and get a returned signature value to compare against header value x-wc-webhook-signature. This example uses WooCommerce so the webhook-source will be the name of the WooCommerce Store that triggered the webhook.

In this example there are webhooks triggered by multiple kinds of events, so a different different secret key needs to be managed for each type of event. The application expects WooCommerce to send only create or update order events. Depending on the type of event, there is a different secret key and signature pair.
