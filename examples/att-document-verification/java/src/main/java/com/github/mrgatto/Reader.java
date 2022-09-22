package com.github.mrgatto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;

import COSE.Encrypt0Message;
import COSE.Message;
import COSE.MessageTag;

/**
 * Attestation Document Infos example.
 * 
 */
public class Reader {

	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		JsonNode node = null;

		try (InputStream is = Reader.class.getClassLoader().getResourceAsStream("attestation_doc.json")) {
			ObjectMapper objectMapper = new ObjectMapper();
			node = objectMapper.readTree(is);
		}

		ByteArrayOutputStream cborBytes = new ByteArrayOutputStream();
		for (JsonNode byteNode : node.get("cbor")) {
			cborBytes.write(byteNode.asInt());
		}
		
		extractAttestationDoc(cborBytes.toByteArray());
	}

	private static void extractAttestationDoc(byte[] bytes) throws Exception {
		Message message = Encrypt0Message.DecodeFromBytes(bytes, MessageTag.Sign1);
		CBORObject cbor = CBORObject.DecodeFromBytes(message.GetContent());

		long timestamp = cbor.get("timestamp").AsInt64();
		System.out.println("timestamp: " + Instant.ofEpochMilli(timestamp));

		String moduleId = cbor.get("module_id").AsString();
		System.out.println("module_id: " + moduleId);

		byte[] userData = cbor.get("user_data").GetByteString();
		System.out.println("user_data: " + new String(userData));

		byte[] certificate = cbor.get("certificate").GetByteString();

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificate));
		System.out.println("certificate:\n " + x509);

		List<CBORObject> pcrs = new ArrayList<>(cbor.get("pcrs").getValues());
		for (int pcr = 0; pcr < pcrs.size(); pcr++) {
			System.out.println("PCR[" + pcr + "]: " + Arrays.toString(pcrs.get(pcr).GetByteString()));
		}

	}

}