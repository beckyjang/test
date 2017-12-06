/**
 * 
 */
package sample.signature;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author USER
 *
 */
public class Signature {

	public static String calculateHMAC(String data, String key) 
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getBytes(), "HmacSAH256"));
		return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes("UTF-8")));
		
	}
}
