package sample.signature;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ApiExplorer {
	static String api_key = "";
	static String api_secret = "";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
		CookieHandler.setDefault(new CookieManager(null, CookiePolicy.ACCEPT_ALL));	// need to handle cookies?
		
		StringBuilder urlBuilder = new StringBuilder("https://api.kjbank.com/api/signature/finacialinstitution/");
		String body = "{\"div\":\"99\", otherchannel:\"ELB\"}";
		
		URL url = new URL(urlBuilder.toString());
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestProperty("Accept", "application/json;charset=UTF-8");
		conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
		conn.setRequestProperty("apikey", api_key);		//Signature 를 사용하기 위해서는 API Key 또는 OAuth 2.0 인증 필수
		conn.setRequestProperty("x-obp-signature-url", Signature.calculateHMAC("POST&/api/signature/finacialinstitution/", api_secret));
		conn.setRequestProperty("x-obp-signature-body", Signature.calculateHMAC(body, api_secret));
		
		conn.setFixedLengthStreamingMode(body.getBytes("UTF-8").length);
		conn.setDoOutput(true);
		
		OutputStream out = conn.getOutputStream();
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(out, "UTF-8"));
		bw.write(body);
		bw.close();
		out.close();
		
		System.out.println("Response Code: " + conn.getResponseCode() + ", Content Encoding: " + conn.getContentEncoding());
		
		BufferedReader rd;
		if (conn.getResponseCode() >= 200 && conn.getResponseCode() <= 300) {
			rd = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
		} else {
			rd = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
		}
		
		StringBuilder sb = new StringBuilder();
		int value;
		while ((value = rd.read()) != -1) { 	//응답 Body Signature 사용 시에는 rd.readLine() 사용금지 (Line Breaker "\r\n" 이 삭제됨)
			sb.append((char)value);
		}
		rd.close();
		
		String resBody = sb.toString();
		String txid = conn.getHeaderField("x-obp-txid");
		String res_x_obp_signature_body = conn.getHeaderField("x-obp-signature-body");	//응답 Header Signature
		String hmacBody = Signature.calculateHMAC(resBody, api_secret);					//응답 Body 로 Signature 생성
		
		if (!res_x_obp_signature_body.equals(hmacBody)) {		//응답받은 Signature 와 생성한 Signature 가 동일한지 체크
			System.out.println("Signature Validation Failed.");
		}
		conn.disconnect();
		
		System.out.println("txid: " + txid);
		System.out.println(resBody);
		
	}
}
