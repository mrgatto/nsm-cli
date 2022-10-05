package com.github.mrgatto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;

/**
 * Attestation Document Validation.
 * 
 * References:
 * 
 * https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
 * https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
 * 
 */
public class Validation {

	public static void main(String[] args) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());

		JsonNode node = null;

		try (InputStream is = Validation.class.getClassLoader().getResourceAsStream("attestation_doc.json")) {
			ObjectMapper objectMapper = new ObjectMapper();
			node = objectMapper.readTree(is);
		}

		ByteArrayOutputStream cborBytes = new ByteArrayOutputStream();
		for (JsonNode byteNode : node.get("cbor")) {
			cborBytes.write(byteNode.asInt());
		}
		
		validateAttestationDoc(cborBytes.toByteArray());
	}

	private static void validateAttestationDoc(byte[] bytes) throws Exception {
		Message message = Encrypt0Message.DecodeFromBytes(bytes, MessageTag.Sign1);
		Sign1Message sign1Message = (Sign1Message) message;

		validateSign1Message(sign1Message);
		System.out.println("Valid COSE signed message");

		validateRootCertificate(sign1Message);
		System.out.println("Valid certificates");
	}

	private static void validateSign1Message(Sign1Message message) throws Exception {
		X509Certificate x509 = getCertificate(message);
		PublicKey key = x509.getPublicKey();

		if (!message.validate(new OneKey(key, null))) {
			throw new CoseException("Could not validate Sign1Message");
		}
	}

	private static void validateRootCertificate(Sign1Message message) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",
				BouncyCastleProvider.PROVIDER_NAME);

		X509Certificate rootCert = null;
		try (InputStream is = Validation.class.getClassLoader().getResourceAsStream("root.pem")) {
			rootCert = (X509Certificate) certificateFactory.generateCertificate(is);
		}

		List<X509Certificate> caBundle = getCABundleCertificate(message);

		// X509Certificate x509 = getCertificate(message);

		CertPath certPath = certificateFactory.generateCertPath(caBundle);

		TrustAnchor trustAnchor = new TrustAnchor(rootCert, null);
		PKIXParameters params = new PKIXParameters(new HashSet<>(Arrays.asList(trustAnchor)));
		params.setRevocationEnabled(false);
		
		// Date expedition of the document
		// Nitro Enclave seems to sign with a 3 hours certificate validity
		params.setDate(DateUtils.parseDate("2021-11-03 22", "YYYY-MM-dd HH"));

		CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
		certPathValidator.validate(certPath, params);
	}

	/**
	 * certificate: cert; the infrastucture certificate used to sign this document,
	 * DER encoded
	 */
	private static X509Certificate getCertificate(Message message) throws Exception {
		CBORObject messageObject = CBORObject.DecodeFromBytes(message.GetContent());
		byte[] certificate = messageObject.get("certificate").GetByteString();

		CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate));
	}

	/**
	 * cabundle: [* cert]; issuing CA bundle for infrastructure certificate
	 */
	private static List<X509Certificate> getCABundleCertificate(Message message) throws Exception {
		CBORObject messageObject = CBORObject.DecodeFromBytes(message.GetContent());
		Collection<CBORObject> cabundle = messageObject.get("cabundle").getValues();

		List<X509Certificate> certificates = new ArrayList<>();

		CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

		for (CBORObject ca : cabundle) {
			byte[] certificate = ca.GetByteString();
			X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate));
			certificates.add(x509);
		}

		return certificates;
	}

}