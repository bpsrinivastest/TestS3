package my.apps.tests3uploadnew;

/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.model.CompleteMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadResult;
import com.amazonaws.services.s3.model.PartETag;
import com.amazonaws.services.s3.model.UploadPartRequest;
import com.amazonaws.services.s3.model.UploadPartResult;


public class Main {

	public static void main(String[] args) throws IOException {

        /*
         * The ProfileCredentialsProvider will return your [default]
         * credential profile by reading from the credentials file located at
         * (~/.aws/credentials).
         */
    	
//        AWSCredentials credentials = null;
//        try {
//            credentials = new ProfileCredentialsProvider().getCredentials();
//	        } catch (Exception e) {
//	            throw new AmazonClientException(
//	                    "Cannot load the credentials from the credential profiles file. " +
//	                    "Please make sure that your credentials file is at the correct " +
//	                    "location (~/.aws/credentials), and is in valid format.",
//	                    e);
//	        }

//			String str_ret = "";
//			UploadFile S3UploadFile = new UploadFile();
//			try {
//				 str_ret = S3UploadFile.putAWSS3Object("MyStudentData2.txt", "MyStudentData2.txt");
//			} catch (Exception e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}
//			
//			return;
		
        	String clientRegion = "us-west-2";
	        String bucketName = "mytestjavabucket" ;

            //String filePath = "src\\AnypointStudio.zip";
            //String keyName = "AnypointStudio.zip";

	        String filePath = "bin\\MyStudentData2.txt";
            String keyName = "MyStudentData1.txt";

            File file = new File(filePath);

            System.out.println("Upload started at: " + (System.currentTimeMillis()/1000/60)) ;         
            
            long contentLength = file.length();
            long partSize = 5 * 1024 * 1024; // Set part size to 5 MB. 

            try {
            	
//            	final ProfileCredentialsProvider credentialsProvider
            	
            	//AWSCredentials credentials 
            	//= new EnvironmentVariableCredentialsProvider().getCredentials();
//                = new ProfileCredentialsProvider().getCredentials();
            	//credentials.
            	
            	
            	
                AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                                        .withRegion(clientRegion)
                                        .withCredentials(new EnvironmentVariableCredentialsProvider())
                                        .build();

                // Create a list of ETag objects. You retrieve ETags for each object part uploaded,
                // then, after each individual part has been uploaded, pass the list of ETags to 
                // the request to complete the upload.
                List<PartETag> partETags = new ArrayList<PartETag>();

                // Initiate the multipart upload.
                InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest(bucketName, keyName);
                InitiateMultipartUploadResult initResponse = s3Client.initiateMultipartUpload(initRequest);

                // Upload the file parts.
                long filePosition = 0;
                for (int i = 1; filePosition < contentLength; i++) {
                    // Because the last part could be less than 5 MB, adjust the part size as needed.
                    partSize = Math.min(partSize, (contentLength - filePosition));

                    // Create the request to upload a part.
                    UploadPartRequest uploadRequest = new UploadPartRequest()
                            .withBucketName(bucketName)
                            .withKey(keyName)
                            .withUploadId(initResponse.getUploadId())
                            .withPartNumber(i)
                            .withFileOffset(filePosition)
                            .withFile(file)
                            .withPartSize(partSize);

                    // Upload the part and add the response's ETag to our list.
                    UploadPartResult uploadResult = s3Client.uploadPart(uploadRequest);
                    partETags.add(uploadResult.getPartETag());

                    filePosition += partSize;
                }

                // Complete the multipart upload.
                CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest(bucketName, keyName,
                        initResponse.getUploadId(), partETags);
                s3Client.completeMultipartUpload(compRequest);
            }
            catch(AmazonServiceException e) {
                // The call was transmitted successfully, but Amazon S3 couldn't process 
                // it, so it returned an error response.
                e.printStackTrace();
            }
            catch(SdkClientException e) {
                // Amazon S3 couldn't be contacted for a response, or the client
                // couldn't parse the response from Amazon S3.
                e.printStackTrace();
            } catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

            System.out.println("Upload ended at: " + (System.currentTimeMillis()/1000/60)) ;        
            
    
            
    }
			
}
