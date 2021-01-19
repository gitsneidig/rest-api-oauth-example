<?
if ($this->request->is('post')) {
    /*/ 
    Create an array of header values to get the source of the incoming payload, 
    the value for what kind of event triggered the webhook, and a signature value
    used to compare to the hash output /*/
    public $headers = array(
		'x-wc-webhook-source'=>$this->request->header('x-wc-webhook-source'),
		'x-wc-webhook-event'=>$this->request->header('x-wc-webhook-event'),
		'x-wc-webhook-signature'=>$this->request->header('x-wc-webhook-signature'),
    );
	
    /*/ 
    Sanitize early	
    Sanitize often /*/
    foreach ($headers as $k=>$v) {
         $headers[$k] = sanitizeIt($v);
    }
	
    /*/
    Use Hook Source value from header
    to determine source and determine which WooCoommerce store sent the payload
    then query for correct config values /*/
    $hook_src = $headers['x-wc-webhook-source'];
    
    /*/ The oAuth methods are in an object /*/
    $oauthObj = new Oauth();
    
    /*/ 
    If the signature provided in the headers matches the hashed secret key
    from the correct source then it's OK to continuing processing the payload 
    Send the request source, the needed headers /*/
    if ($oauthObj->authRequest($hook_src, $headers)) {
	// Get incoming payload
        $data = file_get_contents("php://input");
        // Send data to a method that will process the new order
        $this->add_order($data, $headers);}
    }
}

function sanitizeIt($dirtyVal) {
	return filter_input(INPUT_GET, $dirtyVal, FILTER_SANITIZE_SPECIAL_CHARS);
}

class Oauth {
    public function authRequest($hook_src, $headers) {
	$conds = array('conditions' => array('Stores.wc_hook_source' => $hook_src), 'fields' => array('Stores.wc_created_secret', 'Stores.wc_updated_secret'));
	$this->loadModel('Stores');	
        $store = $this->Stores->find('first', $conds);
        // Get the secret key value that will be used to generate the hash value
        $wc_secret = getSecret($store);
        // Send 
        $send_order = isMatch($headers, $wc_secret);
        return $send_order;
    }
    // Query for the correct secret type and value for the store that sent the payload
    public function getSecret($store) {
        /*/ 
        WooCommerce Webhooks use different Secret for hash authorization depending on action (create|update)
        Determine which event (created|updated) and assign secret key 
        /*/
        switch($headers['x-wc-webhook-event']) {
            case 'created':
                $wc_secret = $store['Stores']['wc_created_secret'];
                break;
            case 'updated':
                $wc_secret = $store['Stores']['wc_updated_secret'];
                break;
        }
        return $wc_secret;
    }
    function isMatch($headers, $wc_secret) {
        // Generate hash using payload and the secret key from the database query
        $hash = hash_hmac('sha256', $data, $wc_secret, true);
            
        // Base64 encode the hash value
        $hashBase64 = base64_encode($hash);
            
        // Get incoming header signature for authorization from the POST header
        $signature = $headers['x-wc-webhook-signature'];			
                
        // Compare output to signature provided by the POST header
        if($hashBase64 == $signature) {
             // There is a match!
            return 1;
        } else {
            // There is no match
            return 0;
        }
}
