package my.apps.tests3uploadnew;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.CopyObjectRequest;
import com.amazonaws.services.s3.model.CopyObjectResult;
import com.amazonaws.services.s3.model.S3ObjectSummary;

public class UploadFile {

	private static final Logger log = LoggerFactory.getLogger(UploadFile.class);

	private javax.crypto.spec.SecretKeySpec signingKey = null;
	private javax.crypto.Mac mac = null;
	private String keyId = null;
	List<Integer> passStatusCodes = Arrays.asList(200, 201, 204, 206, 301, 307);
	List<Integer> failureStatusCodes = Arrays.asList(400, 401, 403, 404, 406, 409, 500, 501);

	public InputStream getAWSS3ObjectAsInputStream(String pathOfFileName, String fileName) throws Exception {
		log.info("Inside getAWSS3ObjectAsInputStream in UploadFile");

		HttpURLConnection httpConn = null;
		InputStream inputStream = null;
		String inputStreamNullCheck = "";
		String awsKeyId = System.getenv("AWS3_ACCESS_KEY_ID");
		String secAccessKey = System.getenv("AWS3_SECRET_ACCESS_KEY");
		String bucketName = System.getenv("AWS3_BUCKET_NAME");

		setKeyId(awsKeyId);
		setKey(secAccessKey);

		String signature = setAWSS3Signature(httpConn, bucketName, pathOfFileName + "/" + fileName, "GET");

		String AWSAuth = "AWS " + keyId + ":" + signature;

		URL url = new URL("http", "s3.amazonaws.com", 80, "/" + bucketName + "/" + pathOfFileName + "/" + fileName);
		httpConn.setFollowRedirects(true);
		httpConn = (HttpURLConnection) url.openConnection();
		setAWSS3Properties(httpConn, "GET", AWSAuth);

		// Send the HTTP GET request.
		int statusCode = httpConn.getResponseCode();

		log.info("Connecting to S3 bucket");
		log.info("bucketName :" + bucketName);
		log.info("pathOfFileName :" + pathOfFileName);
		log.info("fileName :" + fileName);
		if (failureStatusCodes.contains(statusCode)) {
			// Deal with S3 error stream.
			InputStream in = httpConn.getErrorStream();
			if (in != null) {
				String errorStr = getS3ErrorCode(in);
				log.info("Bucket is not accessible");
				log.info("ErrorCode: " + statusCode);
				log.info("Error: " + errorStr);
			}

		} else if (passStatusCodes.contains(statusCode)) { // No error add the files to the bucket.
			log.info("Bucket is accessible with status code:" + statusCode);
			//
			// list the bucket contents
			inputStream = httpConn.getInputStream();
		} else {
			InputStream in = httpConn.getErrorStream();
			if (null != in) {
				log.info("Bucket is not accessible");
				log.info("ErrorCode: " + statusCode);
				log.info("Error: " + getS3ErrorCode(in));
			}
		}

		if (inputStream == null) {
			inputStream = new ByteArrayInputStream(inputStreamNullCheck.getBytes());
		}
		return inputStream;

	}
	// end of getFileFromAWS

	public String putAWSS3Object(String reqPropertyName, String fileName) throws Exception {
		// InputStream is = document.getInputStream();

		File file = new File(fileName);

		String returnValueString = "Y";

		InputStream inputStream = new FileInputStream(file);

		HttpURLConnection httpConn = null;

		String awsKeyId = System.getenv("AWS3_ACCESS_KEY_ID");
		String secAccessKey = System.getenv("AWS3_SECRET_ACCESS_KEY");
		String bucketName = System.getenv("AWS3_BUCKET_NAME");

		setKeyId(awsKeyId);
		setKey(secAccessKey);

//		String signature = setAWSS3Signature(httpConn, bucketName, fileName, "PUT");
		String signature = setAWSS3Signature(httpConn, bucketName, "MyStudentData2.txt", "PUT");
		

		String AWSAuth = "AWS " + keyId + ":" + signature;

//		URL url = new URL("http", "mytestjavabucket.s3.amazonaws.com", 80, "MyStudentData2.txt");
		URL url = new URL("http", "mytestjavabucket.s3.amazonaws.com", 80, "/mytestjavabucket/" + "MyStudentData2.txt");
//		URL url = new URL("http", "mytestjavabucket.s3.amazonaws.com", 80, "/" + bucketName + "/" + fileName);
		httpConn = (HttpURLConnection) url.openConnection();
		setAWSS3Properties(httpConn, "PUT", AWSAuth);

		ByteArrayOutputStream baos = new ByteArrayOutputStream(8196);
		log.info("writting data...");

		byte[] data_one = new byte[512];
		int length_one = 0;
		int totalLength = 0;

		while ((length_one = inputStream.read(data_one)) != -1) {
			baos.write(data_one, 0, length_one);
			totalLength = totalLength + length_one;
		}

		httpConn.setRequestProperty("prefix", reqPropertyName);
		httpConn.setRequestProperty("Content-Length", String.valueOf(totalLength));

		OutputStream os = httpConn.getOutputStream();
		log.info("writting data...");

		InputStream is2 = new FileInputStream(file);

		byte[] data = new byte[512];

		int length = 0;

		while ((length = is2.read(data)) != -1) {
			os.write(data, 0, length);
		}

		os.close();
		is2.close();

		// Send the HTTP PUT request.
		int statusCode = httpConn.getResponseCode();
		String responseStr = httpConn.getResponseMessage();
		

		log.info("Status Code is " + statusCode);

		if (failureStatusCodes.contains(statusCode)) {
			// Deal with S3 error stream.
			InputStream in = httpConn.getErrorStream();
			returnValueString = getS3ErrorCode(in);
			log.info("Error: " + returnValueString);
			log.info("Status Code: " + statusCode);
			return returnValueString;
		} else if (passStatusCodes.contains(statusCode)) { // No error add the files to the bucket.
			log.info("Bucket is accessible.");

			try {
				log.info("reading response...");
				ByteArrayOutputStream baos_two = new ByteArrayOutputStream(8196);
				byte[] dataOut_two = new byte[512];
				InputStream isOut_two = httpConn.getInputStream();
				int lengthOut_two = 0;
				while ((lengthOut_two = isOut_two.read(dataOut_two)) != -1) {
					baos_two.write(dataOut_two, 0, lengthOut_two);
				}
				log.info("finished reading the response");
				Object resp = baos_two.toString();
				log.info("Resp" + resp.toString());
			} catch (Exception excp) {
				log.error(excp.getMessage());
			} finally {
				inputStream.close();
				;
			}

			return returnValueString;
		} else {
			InputStream in = httpConn.getErrorStream();
			returnValueString = getS3ErrorCode(in);
			log.info("Error: " + returnValueString);
			log.info("Status Code: " + statusCode);
			return returnValueString;
		}

	}

	public void setKeyId(String id) {
		this.keyId = id;
	}

	// This method converts AWSSecretKey into crypto instance.
	public void setKey(String AWSSecretKey) throws Exception {
		mac = Mac.getInstance("HmacSHA1");
		byte[] keyBytes = AWSSecretKey.getBytes("UTF8");
		signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		mac.init(signingKey);
	}

	// This method creates S3 signature for a given String.
	public String sign(String data) throws Exception {
		// Signed String must be BASE64 encoded.
		byte[] signBytes = mac.doFinal(data.getBytes("UTF8"));
		String signature = encodeBase64(signBytes);
		return signature;
	}

	public String encodeBase64(byte[] data) {
		String base64 = Base64.getEncoder().encodeToString(data);
		if (base64.endsWith("\r\n"))
			base64 = base64.substring(0, base64.length() - 2);
		return base64;
	}

	public String getS3ErrorCode(InputStream doc) throws Exception {
		String code = null;
		SAXParserFactory parserfactory = SAXParserFactory.newInstance();
		parserfactory.setNamespaceAware(false);
		parserfactory.setValidating(false);
		SAXParser xmlparser = parserfactory.newSAXParser();
		S3ErrorHandler handler = new S3ErrorHandler();
		if (doc != null) {
			xmlparser.parse(doc, handler);
			code = handler.getErrorCode();
			return code;
		} else
			return null;

	}

	// This inner class implements a SAX handler.
	class S3ErrorHandler extends DefaultHandler {
		private StringBuffer code = new StringBuffer();
		private boolean append = false;

		public void startElement(String uri, String ln, String qn, Attributes atts) {
			if (qn.equalsIgnoreCase("Code"))
				append = true;
		}

		public void endElement(String url, String ln, String qn) {
			if (qn.equalsIgnoreCase("Code"))
				append = false;
		}

		public void characters(char[] ch, int s, int length) {
			if (append)
				code.append(new String(ch, s, length));
		}

		public String getErrorCode() {
			return code.toString();
		}
	}

	public String setAWSS3Signature(HttpURLConnection httpCon, String bucket, String fileName, String methodName) {

		// Data needed for signature
		String method = methodName;
		String contentMD5 = "";
		String contentType = "";

		String fmt = "EEE, dd MMM yyyy HH:mm:ss ";
		SimpleDateFormat df = new SimpleDateFormat(fmt, Locale.US);
		df.setTimeZone(TimeZone.getTimeZone("GMT"));
		String date = df.format(new Date()) + "GMT";
		String bucketName = bucket;

		// Generate signature
		StringBuffer buf = new StringBuffer();
		buf.append(method).append("\n");
		buf.append(contentMD5).append("\n");
		buf.append(contentType).append("\n");
		buf.append(date).append("\n");
		buf.append("/").append(bucketName);

		if (fileName != null) {
			buf.append("/").append(fileName);
		}

		String signature = null;
		try {
			signature = sign(buf.toString());
		} catch (Exception excp) {
			excp.printStackTrace();
		}
		;

		return signature;
	}

	public void setAWSS3Properties(HttpURLConnection httpConn, String method, String AWSAuth) {
		String fmt = "EEE, dd MMM yyyy HH:mm:ss ";
		SimpleDateFormat df = new SimpleDateFormat(fmt, Locale.US);
		df.setTimeZone(TimeZone.getTimeZone("GMT"));
		String date = df.format(new Date()) + "GMT";

		httpConn.setDoInput(true);
		httpConn.setDoOutput(true);
		httpConn.setUseCaches(false);
		httpConn.setDefaultUseCaches(false);
		httpConn.setAllowUserInteraction(true);

		try {
			httpConn.setRequestMethod(method);
		} catch (Exception excp) {
		}
		;

		httpConn.setRequestProperty("Date", date);
		httpConn.setRequestProperty("Content-Length", "0");
		httpConn.setRequestProperty("Authorization", AWSAuth);
	}

	/**
	 * To get the latest modified file from AWS S3
	 * 
	 * @param atsSummaryPath
	 * @return
	 */
	public List<String> getJsonFilesFromAwsS3(String inPathOfFile, String prefixOfFile) {
		List<String> s3FileList = new ArrayList<String>();
		String bucketName = System.getenv("AWS3_BUCKET_NAME");
		List<S3ObjectSummary> s3ObjectList = createS3Client().listObjects(bucketName, inPathOfFile + "/")
				.getObjectSummaries();
		if (s3ObjectList != null && !s3ObjectList.isEmpty()) {
			for (S3ObjectSummary s3object : s3ObjectList) {
				log.info("Amazon S3 Latest File Key==>" + s3object.getKey());
				if (s3object != null && s3object.getKey() != null) {
					String fileName = s3object.getKey();
					fileName = fileName.replaceAll("interfaces/ats/input/", "");
					if (fileName.contains(prefixOfFile)) {
						s3FileList.add(fileName);
					}
				}
			}
			log.info("Amazon S3 Json File count ==>" + s3FileList.size());
		}
		return s3FileList;
	}

	public void deleteFilefromS3Folder(String sourceFilePath) {
		String s3BucketName = System.getenv("AWS3_BUCKET_NAME");
		// Verify that the objects were deleted successfully.
		createS3Client().deleteObject(s3BucketName, sourceFilePath);
		log.info(sourceFilePath + " object successfully deleted.");
	}

	public String copyS3Objects(String sourceFile, String destinationFile) {
		String s3BucketName = System.getenv("AWS3_BUCKET_NAME");
		// Copy the object into a new object in the same bucket.
		CopyObjectRequest copyObjRequest = new CopyObjectRequest(s3BucketName, sourceFile, s3BucketName,
				destinationFile);
		CopyObjectResult copyObjectResult = createS3Client().copyObject(copyObjRequest);
		log.info(sourceFile + " object successfully copied to Destination.");
		return copyObjectResult.getETag();
	}

	private AmazonS3 createS3Client() {
		String accessKey = System.getenv("AWS3_ACCESS_KEY_ID");
		String secretKey = System.getenv("AWS3_SECRET_ACCESS_KEY");
		BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(accessKey, secretKey);
		AmazonS3 s3client = AmazonS3ClientBuilder.standard()
				.withCredentials(new AWSStaticCredentialsProvider(basicAWSCredentials)).withRegion(Regions.US_EAST_1)
				.build();
		return s3client;
	}

	public List<String> getFileNamesFromAwsS3(String inPathOfFile, String prefixOfFile) {
		List<String> s3FileList = new ArrayList<String>();
		String bucketName = System.getenv("AWS3_BUCKET_NAME");
		List<S3ObjectSummary> s3ObjectList = createS3Client().listObjects(bucketName, inPathOfFile + "/")
				.getObjectSummaries();
		if (s3ObjectList != null && !s3ObjectList.isEmpty()) {
			for (S3ObjectSummary s3object : s3ObjectList) {
				log.info("Amazon S3 Latest File Key==>" + s3object.getKey());
				if (s3object != null && s3object.getKey() != null) {
					String fileName = s3object.getKey();
					fileName = fileName.replaceAll(inPathOfFile+"/", "");
					if (fileName.contains(prefixOfFile)) {
						s3FileList.add(fileName);
					}
				}
			}
		}
		return s3FileList;
	}
}
