import javax.swing.JPasswordField;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.io.PrintWriter;
import java.io.File;
import javax.swing.*;  
import java.awt.event.*; 
import java.io.FileNotFoundException;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.io.IOException;
import java.io.FileReader;
import java.io.BufferedReader;
import javax.crypto.SecretKey;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.lang.Integer;

public class ThreeFactor {
    
 	String username, password, email, phonenumber, salthash;
    JTextField tfUsername, tfEmail, tfPhoneNumber, usernametxt, passwordtxt;
    JPasswordField pfPassword;
    JLabel lblUsername, lblPassword, lblTitle, lblEmail, lblPhoneNumber, incomplete, usernamelabel, passwordlabel, incompletelogin;
    GridBagLayout gbl;
    GridBagConstraints gbc;
    JButton createscreen, login, create, loginto;
    PrintWriter usernamelist, passwordlist, emaillist, phonelist, saltlist;
    final Random random = new SecureRandom();
    PBEKeySpec spec;
    byte[] hash;
    Base64.Encoder enc;
    JFrame createaccount, loginscreen;
    int index;
    boolean success;
    ArrayList<Byte> hashes = new ArrayList<Byte>();
    ArrayList<Byte> salted = new ArrayList<Byte>();
    public ThreeFactor() {
        //creates PrintWriters for each of the text files that are gonna store user info
    	try {
    		usernamelist = new PrintWriter("UsernameList.txt");
    		passwordlist = new PrintWriter("PasswordList.txt");
    		emaillist = new PrintWriter("EmailList.txt");
    		phonelist = new PrintWriter("PhoneList.txt");
            saltlist = new PrintWriter("SaltList.txt");	
       	} catch (FileNotFoundException e) {
       		e.printStackTrace();
    	}

        //creates textfields
        tfUsername = new JTextField(20);
        pfPassword = new JPasswordField(20);
        tfEmail = new JTextField(20);
        tfPhoneNumber = new JTextField(20);
        usernametxt = new JTextField(20);
        passwordtxt = new JTextField(20);

        //creates labels
        lblUsername = new JLabel("Username");
        lblPassword = new JLabel("Password");
 		lblTitle = new JLabel("Create Account");
 		lblEmail = new JLabel("Email");
 		lblPhoneNumber = new JLabel("Phone Number");
        usernamelabel = new JLabel("Username: ");
        passwordlabel = new JLabel("Password: ");
        incompletelogin = new JLabel();
 		incomplete = new JLabel();

        //creates buttons
 		create = new JButton("Create Account");
        login = new JButton("Login to Account");
        createscreen = new JButton("Create an Account");
        loginto = new JButton("LOGIN");

        //creates grid bahs
        gbl = new GridBagLayout();
        gbc = new GridBagConstraints();
        
        //creates JFrames
        createaccount = new JFrame();
        loginscreen = new JFrame();
        createaccount.setLayout(gbl);
        loginscreen.setLayout(gbl);
 		
        //sets coords for Title in create account
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        createaccount.add(lblTitle, gbc);

        //sets coords for usernames labels for both frames
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        createaccount.add(lblUsername, gbc);
        loginscreen.add(usernamelabel, gbc);
        
        //sets coords for username textfields for both frames
        gbc.gridx = 1;
        gbc.gridwidth = 5;
        gbc.weightx = 1;
        createaccount.add(tfUsername, gbc);
        loginscreen.add(usernametxt, gbc);
        
        //sets coords for password labels for both frames
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 1;
        createaccount.add(lblPassword, gbc);
        loginscreen.add(passwordlabel, gbc);
        
        //sets coords for password textfields for both frames
        gbc.gridx = 1;
        gbc.gridwidth = 5;
        createaccount.add(pfPassword, gbc);
        loginscreen.add(passwordtxt, gbc);

        //creates label for email in create account
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        createaccount.add(lblEmail, gbc);

        //creates textfield for email in create account
        gbc.gridx = 1;
        gbc.gridwidth = 5;
        createaccount.add(tfEmail, gbc);

        //creates label for phone number in create account
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 1;
        createaccount.add(lblPhoneNumber, gbc);

        //creates textfield for phone number in create account
        gbc.gridx = 1;
        gbc.gridwidth = 5;
        createaccount.add(tfPhoneNumber, gbc); 

        //creates button that creates account
        gbc.gridy = 5;
        gbc.gridwidth = 1;
 		createaccount.add(create, gbc);

        //creates button that changes to login screen, and login button that logins to account
        gbc.gridx = 4;
        createaccount.add(login, gbc);
        loginscreen.add(loginto, gbc);

        //creates button that changes to create account screen
        gbc.gridx = 5;
        loginscreen.add(createscreen, gbc);

        //creates label that appear if login or create account fails
 		gbc.gridy = 6;
 		createaccount.add(incomplete, gbc);
        loginscreen.add(incompletelogin, gbc);

        //actionlistener for create account button
 		create.addActionListener(new ActionListener() {
 			public void actionPerformed(ActionEvent ae) {
                //gets text from textfields
 				username = tfUsername.getText();
 				email = tfEmail.getText();
 				phonenumber = tfPhoneNumber.getText();
 				password = String.valueOf(pfPassword.getPassword());
                incomplete.setText("Account Created");
                    
                //calls hasher method to store hashed password and salt
                hasher(password);

                //adds textfields to respective text files
     			usernamelist.println(username);
     			emaillist.println(email);
     			phonelist.println(phonenumber);

                //flushes data
     			usernamelist.flush();
     			emaillist.flush();
     			phonelist.flush();

                //resets textfields
                tfUsername.setText("");
                tfEmail.setText("");
                tfPhoneNumber.setText("");
                pfPassword.setText("");
     		}
     	});

        //changes screen to login screen
        login.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                createaccount.setVisible(false);
                loginscreen.setVisible(true);
                incompletelogin.setText("");
                incomplete.setText("");
            }
        });

        //changes screen to create account screen
        createscreen.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                createaccount.setVisible(true);
                loginscreen.setVisible(false);
                incompletelogin.setText("");
                incomplete.setText("");
            }
        });

        //actionlistener for log into account button
        loginto.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                success = false;
                int i;
                BufferedReader reader;
                BufferedReader saltreader;

                //gets text from login textfields
                password = passwordtxt.getText();
                username = usernametxt.getText();

                //checks if any required textfields are empty
                if(password.isEmpty() || username.isEmpty()) {
                    incompletelogin.setText("INCOMPLETE FIELD(S)");
                } else {
                    incompletelogin.setText("");
                    try {
                        i = 0;
                        //creates buffered reader to read through username textfile
                        reader = new BufferedReader(new FileReader("UsernameList.txt"));
                        String storedusername = reader.readLine();

                        //checks to see if login username matches any usernames stored and stores index
                        while(storedusername != null) {
                            if(username.equals(storedusername)) {
                                index = i;
                                break;
                            }
                            storedusername = reader.readLine();
                            i++;
                        }
                        reader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {
                        int j = 0;

                        //creates buffered readers for password and saltlist
                        reader = new BufferedReader(new FileReader("PasswordList.txt"));
                        saltreader = new BufferedReader(new FileReader("SaltList.txt"));
                        String storedpassword = new String(reader.readLine());
                        String storedsalt = new String(saltreader.readLine());

                        //checks to see if the login password matches the password at the previously found index
                        while(storedpassword != null) {
                            if(j == index) {
                                //checks if passwords match
                                boolean match = check(password, storedpassword, storedsalt);
                                //if passwords match, login successful
                                if(match == true) {
                                    success = true;
                                    System.out.println("Login Successful");
                                    break;
                                }
                            }
                            j++;
                            storedpassword = reader.readLine();
                            storedsalt = saltreader.readLine();
                        }
                        //if passwords don't match or password doesn't exist at given index, login fails
                        if(success == false) {
                            System.out.println("No such account exists");
                        }
                        reader.close();
                        saltreader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        //sets all contents within their frames to their respective sizes
        createaccount.pack();
        loginscreen.pack();

        //initially sets create account screen to be visible
        createaccount.setVisible(true);
        loginscreen.setVisible(false);

        //exit on close
        createaccount.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginscreen.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    //checks to see if the given password matches the stored password
    public boolean check(String password, String stored, String salty) {
        char[] charpass = password.toCharArray();
        byte[] bytestored = stored.getBytes();
        byte[] bytesalt =  salty.getBytes();
        System.out.println("stored salt length: " + bytesalt.length);
        System.out.println("stored pass length: " + bytestored.length);
        byte[] hashedpass = new byte[32];
        hashedpass = hasher(charpass, bytesalt);
        for(int i = 0; i < hashedpass.length; i++) {
            hashedpass[i] = (byte)Math.abs(hashedpass[i]);
        }
        Arrays.fill(charpass, Character.MIN_VALUE);

        System.out.println("Salt " + Arrays.toString(bytesalt));
        
        System.out.println("Stored pass: " + Arrays.toString(bytestored));
        
        

        System.out.println("New pass:    " + Arrays.toString(hashedpass));
        



        if(hashedpass.length != bytestored.length) {
            return false;
        }
        for(int i = 0; i < hashedpass.length; i++) {
            if(hashedpass[i] != bytestored[i]) {
                return false;
            }
        }
        return true;
    }

    //stores hashed password and salt in respective text files
    public void hasher(String password) {
        char[] charedpassword = password.toCharArray();
        byte[] salt = getSalt();
        spec = new PBEKeySpec(charedpassword, salt, 10000, 256);
        Arrays.fill(charedpassword, Character.MIN_VALUE);

        //checks if any of the required textfields are empty
        if(username.isEmpty() || password.isEmpty() || email.isEmpty() || phonenumber.isEmpty()) {
            incomplete.setText("INCOMPLETE FIELD(S)");
        } else {
            //continues hashing
            try {   
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                hash = factory.generateSecret(spec).getEncoded();
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
            } finally {
                spec.clearPassword();
            }
        }
        for(int i = 0; i < hash.length; i++) {
            hash[i] = (byte)Math.abs(hash[i]);
        }

        String insertsalt = new String(salt);
        String inserthash = new String(hash);

        System.out.println("Salt before stored " + Arrays.toString(salt));
        System.out.println("Within 1 param hasher: " + Arrays.toString(hash));

        saltlist.println(insertsalt);
        passwordlist.println(inserthash);
        saltlist.flush();
        passwordlist.flush();
    }

    //generates salt
    public byte[] getSalt() {
        byte[] salt = new byte[16];
        for(int i = 0; i < salt.length; i++) {
            salt[i] = (byte)(Math.random()*100);
        }
        //random.nextBytes(salt);
        return salt;
    }

    //returns byte[] of the hashed password that uses the given salt
    public byte[] hasher(char[] password, byte[] salty) {

        System.out.println("Salt " + Arrays.toString(salty));

        spec = new PBEKeySpec(password, salty, 10000, 256);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return factory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    //main
    public static void main(String args[]) {
        ThreeFactor test = new ThreeFactor();
    }
}