import java.io.*;
import java.util.*;
import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.io.FileWriter;
import java.util.ArrayList;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

  

class Main {
  public static void main(String[] args) {
    Scanner in = new Scanner(System.in);
    HashMap<String, boolean[]> bloomFilterValue = new HashMap<>();
    int bit_array_size = 1600;
    int bit_array_size_for_comm_pass = 38466;
    int salt_Length = 20;
    String enteredID;
    String hassPassword;
    

    try{
        //------------------------------------------------------------------------- file connections 
        File userFileRead = new File("user.txt");
        File commonPass1 = new File("rockyou-8.txt");
        File commonPass2 = new File("rockyou-10.txt");
        File commonPass3 = new File("rockyou-12.txt");
        FileWriter userFileWrite = new FileWriter(userFileRead, true);
        Scanner myReader = new Scanner(userFileRead);
        Scanner comPassReader1 = new Scanner(commonPass1);
        Scanner comPassReader2 = new Scanner(commonPass2);
        Scanner comPassReader3 = new Scanner(commonPass3);



        boolean [] most_common_pass_bloom_8 = new boolean [bit_array_size_for_comm_pass];
        boolean [] most_common_pass_bloom_10 = new boolean [bit_array_size_for_comm_pass];
        boolean [] most_common_pass_bloom_12 = new boolean [bit_array_size_for_comm_pass];

        while (comPassReader1.hasNextLine()) {
            String pass = comPassReader1.nextLine();
            most_common_pass_bloom_8 = make_bloom_filter_for_comm_pass(pass, bit_array_size_for_comm_pass);

            // for(int i = 0; i < bit_array_size_for_comm_pass ; i++){
            //   if(most_common_pass_bloom_8[i] == true)
            //     System.out.print(most_common_pass_bloom_8[i]  + " ");
            // }
        }

        while (comPassReader2.hasNextLine()) {
            String pass = comPassReader2.nextLine();
            most_common_pass_bloom_10 = make_bloom_filter_for_comm_pass(pass, bit_array_size_for_comm_pass);
        }

        while (comPassReader3.hasNextLine()) {
            String pass = comPassReader3.nextLine();
            most_common_pass_bloom_12 = make_bloom_filter_for_comm_pass(pass, bit_array_size_for_comm_pass);
        }



        //------------------------------------------------------------------------- count number of lines in file 
        BufferedReader reader = new BufferedReader(new FileReader("user.txt"));
        int lines = 0;
        while (reader.readLine() != null) lines++;
        reader.close();

        //------------------------------------------------------------------------- user register 
        
        System.out.println("\n\nPlease enter user id: ");
        String ID = in.nextLine();


        int counter2 = 0;

        //------------------------------------------------------------------------- check unique user ID 
        if(userFileRead.length() == 0) {

          //in.nextLine();
                   System.out.println("Please enter user password: ");
                   String pass = in.nextLine();

                   // *************************************************************** check using F1

                  boolean [] entered_pass_bloom_filter = new boolean [bit_array_size_for_comm_pass];
                  entered_pass_bloom_filter= make_bloom_filter_for_comm_pass(pass, bit_array_size_for_comm_pass);

                   boolean status__for_8 = find_similarity( most_common_pass_bloom_8, entered_pass_bloom_filter, bit_array_size_for_comm_pass);
                  
                   boolean status__for_10 = find_similarity( most_common_pass_bloom_10, entered_pass_bloom_filter, bit_array_size_for_comm_pass);

                   boolean status__for_12 = find_similarity( most_common_pass_bloom_12, entered_pass_bloom_filter, bit_array_size_for_comm_pass);

                   if(status__for_8 == true && status__for_10 == true && status__for_12 == true) {
                        
                      // --------------------------------------------------- solting the password
                      
                      String salt = getAlphaNumericString(salt_Length);
                      String saltedPass = pass + salt;
                      hassPassword = Md5(saltedPass);

                      //------------------------------------------------------------------------- add to a text file
                      userFileWrite.write(ID + " " + salt + " " + hassPassword + "\n");
                      userFileWrite.close();

                      String password1 = "anbcd";
                      boolean [] old_password_bloom_filter_value = new boolean [bit_array_size];
                      old_password_bloom_filter_value = make_bloom_filter_value_for_passowoard(pass, bit_array_size);
                      bloomFilterValue.put(ID, old_password_bloom_filter_value);
                      System.out.println("User has successfully registered to the system.");

                   }

                   else {
                      System.out.println("Sorry. We can not except your password.\n Please run the program again to register.\n\n");
                      System.exit(0);
                   }

        }

        else {

          while (myReader.hasNextLine()) {
           String idToCheck = myReader.next();
           myReader.next();
           myReader.next();
           
           //------------------------------------------------------------------------- if match get new ID
           if(ID.equals(idToCheck)) {
              System.out.println("Sorry ID has taken.\nPlease run the program again to register.");
              System.exit(0);
           }

           //------------------------------------------------------------------------- else get password and continue
           else {
             counter2++;
             if(lines == counter2) {
                   //in.nextLine();
                   System.out.println("Please enter user password: ");
                   String pass = in.nextLine();

                  //  // *************************************************************** check using F1
                     boolean [] entered_pass_bloom_filter = new boolean [bit_array_size_for_comm_pass];
                  entered_pass_bloom_filter= make_bloom_filter_for_comm_pass(pass, bit_array_size_for_comm_pass);

                   boolean status__for_8 = find_similarity( most_common_pass_bloom_8, entered_pass_bloom_filter, bit_array_size_for_comm_pass);
                  
                   boolean status__for_10 = find_similarity( most_common_pass_bloom_10, entered_pass_bloom_filter, bit_array_size_for_comm_pass);

                   boolean status__for_12 = find_similarity( most_common_pass_bloom_12, entered_pass_bloom_filter, bit_array_size_for_comm_pass);

                   if(status__for_8 == true && status__for_10 == true && status__for_12 == true) {
                        

                      // --------------------------------------------------- solting the password
                      
                      String salt = getAlphaNumericString(salt_Length);
                      String saltedPass = pass + salt;
                      hassPassword = Md5(saltedPass);

                      //------------------------------------------------------------------------- add to a text file
                      userFileWrite.write(ID + " " + salt + " " + hassPassword + "\n");
                      userFileWrite.close();

                      boolean [] old_password_bloom_filter_value = new boolean [bit_array_size];
                      old_password_bloom_filter_value = make_bloom_filter_value_for_passowoard(pass, bit_array_size);
                      bloomFilterValue.put(ID, old_password_bloom_filter_value);
                      
                      System.out.println("User has successfully registered to the system.");
                      break;

                   }

                   else {
                      System.out.println("Sorry. We can not except your password.\n Please run the program again to register.\n\n");
                      System.exit(0);
                   }


                }

                else continue;
           }

           
          }

        }


        System.out.println("\n\nPRESS 0: To exit the System.");
        int enter = in.nextInt();
        if(enter == 0) {
          System.exit(0);
        }
        else {
          System.out.println("\n\nPlease follow the instructions");
        }

        // ---------------------------------------------------------------------- Log-in
        System.out.println("\n\nPlease enter user id to log-in: ");
        in.nextLine();
        enteredID = in.nextLine();
        //System.out.println("Line: " + lines);

         //------------------------------------------------------------------------- check UID in file
         int counter1 = 0;
         while (myReader.hasNextLine()) {
            String userID = myReader.next();

            //------------------------------------------------------------------------- if match get salt and hash
            if(enteredID.equals(userID)) {
                //System.out.println(userID);
                String userSalt = myReader.next();
                String userPassHash = myReader.next();
                //System.out.println(userPass);

                //------------------------------------------------------------ get password and make new hash with salt
                System.out.println("Please enter user password: ");
                //in.nextLine();
                String enteredPass = in.nextLine();
                String hashEnteredPass = Md5(enteredPass + userSalt);

                //------------------------------------------------------------------- if match successfully Logged in
                if(userPassHash.equals(hashEnteredPass)) {
                    System.out.println("Thank You. \nYou have successfully Logged in.\n\n\n");

                    System.out.println("\n\n********** Please change your password **********");
                    ////------------------------------------------------------------------- bloom filter F2
                    boolean [] old_password_bloom_filter_value_s;
                    if (bloomFilterValue.containsKey(enteredID)) {
                            old_password_bloom_filter_value_s = bloomFilterValue.get(enteredID);
                            boolean [] new_password_bloom_filter_value = new boolean [bit_array_size];

                            System.out.println("Enter new password: ");
                            String new_password = in.nextLine();
                            new_password_bloom_filter_value = make_bloom_filter_value_for_passowoard(new_password, bit_array_size);

                            boolean status = to_check_the_acceptance_of_a_password( old_password_bloom_filter_value_s, new_password_bloom_filter_value, bit_array_size);


                            if( status == true){
                                String newSalt = getAlphaNumericString(salt_Length);
                                String newHassPassword = Md5(newSalt + new_password);
                                modifyFile("user.txt", userPassHash, newHassPassword);
                                System.out.println("Thank you for registering in our system.\n\n");
                                System.exit(0);
                            }
                          
                            else 
                                System.out.println("Sorry. We can not except your password.\n Please run the program again to register.\n\n");
                                System.exit(0);
                      }  
                    
                }

                //----------------------------------------------------------------- else print error
                else {
                    System.out.println("Wrong Password.....\n\n\n");
                    System.exit(0);
                    break;
                }
    
            }

            //---------------------------------------------------- check whole file to get valid user else print error 
            else {
                  counter1++;
                  if(lines == counter1) {
                               System.out.println("Test Line 4");
                      System.exit(0);
                  }

                  else continue;
            }  
        }
    }
     
     catch (IOException e) {
      System.out.println("Sorry file did not created");
      e.printStackTrace();
    }

  }


  public static String getAlphaNumericString(int n) {
  
       
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz";
  
        StringBuilder sb = new StringBuilder(n);
  
        for (int i = 0; i < n; i++) {
            int index = (int)(AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }
  
        return sb.toString();
    }


  public static String Md5(String password){
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] messageDigest = md.digest(password.getBytes());

			BigInteger no = new BigInteger(1, messageDigest);

			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}

			return hashtext;
		}

		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}



  public static byte[] SHA256(String input) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(input.getBytes(StandardCharsets.UTF_8));
	}
	
	public static String toHexString(byte[] hash)	{
	
		BigInteger number = new BigInteger(1, hash);
		StringBuilder hexString = new StringBuilder(number.toString(16));
		while (hexString.length() < 32)	{
			hexString.insert(0, '0');
		}
		return hexString.toString();
	}



public static int hash_function_1(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (1 * sha256);
        //System.out.println("hash = " + hash + "\nmd5 = " + md5 + "\n sha256 = " + sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
        //System.out.println("Num = " + hash + "\nsize = " + bit_array_size);
      
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_2(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (2 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_3(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (3 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_4(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (4 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_5(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (5 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_6(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (6 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_7(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (7 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_8(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (8 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_9(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (9 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_10(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (10 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_11(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (11 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_12(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (12 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_13(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (13 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_14(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (14 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }



public static int hash_function_15(String temp_pass_part, int bit_array_size){
    long hash = 0;
    try{
        long md5 = new BigInteger(Md5(temp_pass_part), 16).intValue();
        long sha256 = new BigInteger(toHexString(SHA256(temp_pass_part)),16).intValue();
        hash = md5 + (15 * sha256);
        hash = hash % bit_array_size;
        if (hash < 0) {
            hash += bit_array_size;
        }
    }
    
    catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
    
    return (int)hash;
  }




public static boolean[] make_bloom_filter_value_for_passowoard(String given_password, int bit_array_size){
    String temp_pass = "_" + given_password + "_";
    String temp_pass_part;
    ArrayList<boolean[]> filter_list = new ArrayList<boolean[]>();

    for(int i = 0; i < temp_pass.length() - 1; i++) {
        boolean []temp_user_pass = new boolean[bit_array_size];
        Arrays.fill(temp_user_pass, false);

        String char1 = String.valueOf(temp_pass.charAt(i));
        String char2 = String.valueOf(temp_pass.charAt(i+1));
        temp_pass_part = char1 + char2;

        int pos1 = hash_function_1(temp_pass_part, bit_array_size);
        temp_user_pass[pos1] = true;

        int pos2 = hash_function_2(temp_pass_part, bit_array_size);
        temp_user_pass[pos2] = true;

        int pos3 = hash_function_3(temp_pass_part, bit_array_size);
        temp_user_pass[pos3] = true;

        int pos4 = hash_function_4(temp_pass_part, bit_array_size);
        temp_user_pass[pos4] = true;

        int pos5 = hash_function_5(temp_pass_part, bit_array_size);
        temp_user_pass[pos5] = true;

        int pos6 = hash_function_6(temp_pass_part, bit_array_size);
        temp_user_pass[pos6] = true;

        int pos7 = hash_function_7(temp_pass_part, bit_array_size);
        temp_user_pass[pos7] = true;

        int pos8 = hash_function_8(temp_pass_part, bit_array_size);
        temp_user_pass[pos8] = true;

        int pos9 = hash_function_9(temp_pass_part, bit_array_size);
        temp_user_pass[pos9] = true;

        int pos10 = hash_function_10(temp_pass_part, bit_array_size);
        temp_user_pass[pos10] = true;

        int pos11 = hash_function_11(temp_pass_part, bit_array_size);
        temp_user_pass[pos11] = true;

        int pos12 = hash_function_12(temp_pass_part, bit_array_size);
        temp_user_pass[pos12] = true;

        int pos13 = hash_function_13(temp_pass_part, bit_array_size);
        temp_user_pass[pos13] = true;

        int pos14 = hash_function_14(temp_pass_part, bit_array_size);
        temp_user_pass[pos14] = true;

        int pos15 = hash_function_15(temp_pass_part, bit_array_size);
        temp_user_pass[pos15] = true;


        // System.out.println("Pos 1 = " + pos1);
        // System.out.println("Pos 2 = " + pos2);
        // System.out.println("Pos 3 = " + pos3);
        // System.out.println("Pos 4 = " + pos4);
        // System.out.println("Pos 5 = " + pos5);
        // System.out.println("Pos 6 = " + pos6);
        // System.out.println("Pos 7 = " + pos7);
        // System.out.println("Pos 8 = " + pos8);
        // System.out.println("Pos 9 = " + pos9);
        // System.out.println("Pos 10 = " + pos10);
        // System.out.println("Pos 11 = " + pos11);
        // System.out.println("Pos 12 = " + pos12);
        // System.out.println("Pos 13 = " + pos13);
        // System.out.println("Pos 14 = " + pos14);
        // System.out.println("Pos 15 = " + pos15);


        filter_list.add(temp_user_pass);
  }

    boolean [] final_filtered_password  = new boolean[bit_array_size];
    Arrays.fill(final_filtered_password, false);

    for(int j = 0; j < filter_list.size(); j++){
        boolean [] current_filtered_pass = new boolean[bit_array_size];
        current_filtered_pass = filter_list.get(j);
          // System.out.println("\n\n");
        for(int k = 0; k < bit_array_size; k++){
          // System.out.print(current_filtered_pass[k] + " ");
          final_filtered_password[k] = final_filtered_password[k] |  current_filtered_pass[k];
        }

    }
    
    // System.out.println("\n\n");
    // for(int i = 0; i < bit_array_size; i++){
    //   System.out.print(final_filtered_password[i] + " ");
    // }

    return final_filtered_password;
    
  }




public static int common_true_values(boolean [] bloom_filter_value_1, boolean [] bloom_filter_value_2, int bit_array_size) {

      int count_the_true_value = 0;
      for(int i = 0; i < bit_array_size; i++) {
        if(bloom_filter_value_1[i] == true && bloom_filter_value_2[i] == true) 
            count_the_true_value++;
          }
      // System.out.println("Common true value: " + count_the_true_value);
      return count_the_true_value;

  }



public static int number_of_true_value(boolean [] bloom_filter_value, int bit_array_size){
        int count_the_true_value = 0;
        for(int i = 0; i < bit_array_size; i++){
          if(bloom_filter_value[i] == true) 
              count_the_true_value++;
            }
      //System.out.println("Number true value: " + count_the_true_value);
      return count_the_true_value;
}


public static double Jaccard_coefficient(int common_in_two_filter, int true_value_in_pass1, int true_value_in_pass2) {

    double similarity_in_password = ( common_in_two_filter / ( (true_value_in_pass1 + true_value_in_pass2) - common_in_two_filter ) ) * 100;

    double a1 = true_value_in_pass1 + true_value_in_pass2;
    double a2 = a1 - common_in_two_filter;
    double a3 = common_in_two_filter / a2;
    double a4 = a3 * 100;

    //System.out.println("a1 = " + a1 + " a2 = " + a2 + " a3 = " + a3 + " a4 = " + a4);

    //System.out.println("1. Number true value: " + true_value_in_pass1 + " 2. Number true value: " + true_value_in_pass2 + " Common true value: " + common_in_two_filter);
    //System.out.println("From JC = " + similarity_in_password);

    return a4; 

}




public static boolean to_check_the_acceptance_of_a_password(boolean [] old_password_filtered_value, boolean [] new_password_filtered_value, int bit_array_size) {


    int number_of_true_value_in_pass1 = number_of_true_value(old_password_filtered_value, bit_array_size);

    int number_of_true_value_in_pass2 = number_of_true_value(new_password_filtered_value, bit_array_size);


    int true_values_in_two_Bloom_filters = common_true_values (old_password_filtered_value, new_password_filtered_value, bit_array_size);

      double similarity = Jaccard_coefficient (true_values_in_two_Bloom_filters, number_of_true_value_in_pass1, number_of_true_value_in_pass2);
      System.out.println("\nFrom Acc = " + similarity);

      if (similarity < 10) 
          return true;

      else return false;

}



public static void modifyFile(String filePath, String oldString, String newString)
    {
        File fileToBeModified = new File(filePath);
         
        String oldContent = "";
         
        BufferedReader reader = null;
         
        FileWriter writer = null;
         
        try
        {
            reader = new BufferedReader(new FileReader(fileToBeModified));
             
            //Reading all the lines of input text file into oldContent
             
            String line = reader.readLine();
             
            while (line != null) 
            {
                oldContent = oldContent + line + System.lineSeparator();
                 
                line = reader.readLine();
            }
             
            //Replacing oldString with newString in the oldContent
             
            String newContent = oldContent.replaceAll(oldString, newString);
             
            //Rewriting the input text file with newContent
             
            writer = new FileWriter(fileToBeModified);
             
            writer.write(newContent);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                //Closing the resources
                 
                reader.close();
                 
                writer.close();
            } 
            catch (IOException e) 
            {
                e.printStackTrace();
            }
        }
    }

    
//hash1
public static int h1(String s, int bit_array_size) {
    int hash = 0;
    for (int i = 0; i < s.length(); i++) {
      hash = (hash + ((int)s.charAt(i)));
      hash = hash % bit_array_size;
    }

    if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

//hash2
public static int h2(String s, int bit_array_size) {
  int hash = 1;
  for (int i = 0; i < s.length(); i++) {
    hash = hash + (int)Math.pow(19, i) * s.charAt(i);
    hash = hash % bit_array_size;
  }

  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}


// // hash 3

public static int h3(String s, int bit_array_size) {
    int hash = 7;
    for (int i = 0; i < s.length(); i++) {
      hash = (hash * 31 + s.charAt(i)) % bit_array_size;
    }

  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

// // hash 4

public static int h4(String s, int bit_array_size){
    int hash = 3;
    int p = 7;
    for (int i = 0; i < s.length(); i++) {
        hash += hash * 7 + s.charAt(0) * Math.pow(p, i);
        hash = hash % bit_array_size;
    }

  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

//hash5

public static int h5(String s, int bit_array_size) {
  long hash = 0, m = 1;
  for (int i = 0; i < s.length(); i++) {
    m = (i % 4 == 0) ? 1 : m * 256;
    hash += s.charAt(i) * m;
  }

    hash = (int)(Math.abs(hash) % bit_array_size);
  if (hash < 0) {
            hash += bit_array_size;
        }

  return (int)hash;
}


// // hash6

public static int h6(String s, int bit_array_size) {
    int hash = 1;
    for (int i = 0; i < s.length(); i++) {
        hash = hash + (int)Math.pow(19, i) * s.charAt(i);
        hash = hash % bit_array_size;
    }

  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

// //hash7

public static int h7(String s, int bit_array_size) {
    int g=31;
    int hash=0;
    for (int i=0;i<s.length();i++) {
        hash =g*hash+s.charAt(i);
        hash = hash % bit_array_size;
    }

      hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

// //hash8

public static int h8(String s, int bit_array_size) {
    int hash= 0;
    for (int i = 0; i < s.length(); i++) {
        hash += s.charAt(i);
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    hash = hash % bit_array_size;

  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

// //hash9

public static int h9(String s, int bit_array_size) {
    int hash = 0;
    for (int i = 0; i < s.length(); ++i) {
        int r = s.charAt(i);
        hash = r + (hash << 6) + (hash << 16) - hash;
    }
    hash = hash % bit_array_size;

  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

// //hash10

public static int h10(String s, int bit_array_size) {
    int fnv_prime = 0x811C9DC5;
    int hash = 0;
    int i = 0;
    int length = s.length();

    for (i = 0; i < length; i++) {
        hash *= fnv_prime;
        hash ^= (s.charAt(i));
    }
    hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}

 //hash11

public static int h11(String s, int bit_array_size) {
    char ch[];
    ch = s.toCharArray();
    int i, hash;
    
    for (hash=0, i=0; i < s.length(); i++) {
      hash += ch[i];
    }

  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}


 //hash11
public static int h12(String str, int bit_array_size) {
    int p = 31;
    int power_of_p = 1;
    int hash= 0;
     for(int i = 0; i < str.length(); i++)
    {
        hash= (hash+ (str.charAt(i) - 'a' + 1) * power_of_p) % bit_array_size;
        power_of_p = (power_of_p * p) % bit_array_size;
    }
  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;
}


//hash 13
public static int h13(String s, int bit_array_size) {
  long hash = 1125899906842597L; 
  int len = s.length();

  for (int i = 0; i < len; i++) {
    hash = 31*hash + s.charAt(i);
  }
  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return (int)hash;
}



//hash14

public static int h14(String s , int bit_array_size) {
    int hash = 0;
    int i;

    for (i = 0; i < s.length(); ++i) 
        hash = 33 * hash + s.charAt(i);

    hash = hash % bit_array_size;

  if (hash < 0) {
            hash += bit_array_size;
        }

  return hash;

}




//hash 15

public static int h15(String s, int bit_array_size) {
    long hash = 0;

    for (int i = 0; i < s.length(); i++) {
        hash = ((hash << 5) + hash) + s.charAt(i);
    }

  hash = hash % bit_array_size;
  if (hash < 0) {
            hash += bit_array_size;
        }

  return (int)hash;
}


public static boolean[] make_bloom_filter_for_comm_pass(String given_password, int bit_array_size){
    ArrayList<boolean[]> filter_list = new ArrayList<boolean[]>();

    for(int i = 0; i < given_password.length() - 1; i++) {
        boolean []temp_user_pass = new boolean[bit_array_size];
        Arrays.fill(temp_user_pass, false);


        int pos1 = h1(given_password, bit_array_size);
        temp_user_pass[pos1] = true;

        int pos2 = h2(given_password, bit_array_size);
        temp_user_pass[pos2] = true;

        int pos3 = h3(given_password, bit_array_size);
        temp_user_pass[pos3] = true;

        int pos4 = h4(given_password, bit_array_size);
        temp_user_pass[pos4] = true;

        int pos5 = h5(given_password, bit_array_size);
        temp_user_pass[pos5] = true;

        int pos6 = h6(given_password, bit_array_size);
        temp_user_pass[pos6] = true;

        int pos7 = h7(given_password, bit_array_size);
        temp_user_pass[pos7] = true;

        int pos8 = h8(given_password, bit_array_size);
        temp_user_pass[pos8] = true;

        int pos9 = h9(given_password, bit_array_size);
        temp_user_pass[pos9] = true;

        int pos10 = h10(given_password, bit_array_size);
        temp_user_pass[pos10] = true;

        int pos11 = h11(given_password, bit_array_size);
        temp_user_pass[pos11] = true;

        int pos12 = h12(given_password, bit_array_size);
        temp_user_pass[pos12] = true;

        int pos13 = h13(given_password, bit_array_size);
        temp_user_pass[pos13] = true;

        int pos14 = h14(given_password, bit_array_size);
        temp_user_pass[pos14] = true;

        int pos15 = h15(given_password, bit_array_size);
        temp_user_pass[pos15] = true;


        // System.out.println("Pos 1 = " + pos1);
        // System.out.println("Pos 2 = " + pos2);
        // System.out.println("Pos 3 = " + pos3);
        // System.out.println("Pos 4 = " + pos4);
        // System.out.println("Pos 5 = " + pos5);
        // System.out.println("Pos 6 = " + pos6);
        // System.out.println("Pos 7 = " + pos7);
        // System.out.println("Pos 8 = " + pos8);
        // System.out.println("Pos 9 = " + pos9);
        // System.out.println("Pos 10 = " + pos10);
        // System.out.println("Pos 11 = " + pos11);
        // System.out.println("Pos 12 = " + pos12);
        // System.out.println("Pos 13 = " + pos13);
        // System.out.println("Pos 14 = " + pos14);
        // System.out.println("Pos 15 = " + pos15);


        filter_list.add(temp_user_pass);
  }

    boolean [] final_filtered_password  = new boolean[bit_array_size];
    Arrays.fill(final_filtered_password, false);

    for(int j = 0; j < filter_list.size(); j++){
        boolean [] current_filtered_pass = new boolean[bit_array_size];
        current_filtered_pass = filter_list.get(j);
          // System.out.println("\n\n");
        for(int k = 0; k < bit_array_size; k++){
          // System.out.print(current_filtered_pass[k] + " ");
          final_filtered_password[k] = final_filtered_password[k] |  current_filtered_pass[k];
        }

    }
    
    // System.out.println("\n\n");
    // for(int i = 0; i < bit_array_size; i++){
    //   System.out.print(final_filtered_password[i] + " ");
    // }

    return final_filtered_password;
    
  }


  public static boolean find_similarity(boolean [] old_password_filtered_value, boolean [] new_password_filtered_value, int bit_array_size) {

      int checker = 0;
      for(int i = 0; i < bit_array_size; i++) {
          if(new_password_filtered_value[i] == true && old_password_filtered_value[i] == true) {
              checker++;
          }
      }

      double sim = (checker/bit_array_size)*100;
      System.out.println("\nsimilarity = " + sim + "checker: " + checker);

      boolean similarity;
      if(checker < 10) similarity = true;
      else similarity = false;

      System.out.println("\nsimilarity = " + similarity);

      return similarity;
}



}


  