<?php

/**
 * Plugin Name:       Secret Word Two Step Authentication
 * Plugin URI:        https://claytonkreisel.com/plugins/secret-word-two-step-authentication/
 * Description:       Handle the basics with this plugin.
 * Version:           1.0
 * Requires at least: 5.2
 * Requires PHP:      7.0
 * Author:            Clayton Kreisel
 * Author URI:        https://claytonkreisel.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       swtsa
 */


define('SWTSA_DIR', plugin_dir_path( __FILE__ ));
define('SWTSA_JSON_DIR', SWTSA_DIR . 'assets/json/');

class SWTSA_Users_Security {

    //Build the security class
    public static function init(){

        //Handle wordpress login page of admin section
        self::wordpress_admin_login();

        //Handle the add/edit users on the portal
        self::admin_user_management();

        //User Registration Global
        self::user_registration();

    }

    //Force every user to have a gamer tag
    public static function user_registration(){
        add_action( 'user_register', array('SWTSA_Users_Security', 'associate_gamer_tag'), 90, 1 );
    }

    //Return the secret word list (provide a list id between 1-9)
    public static function get_secret_word_list($list_id){
        if(!$list_id){
            return array();
        }
        return json_decode(file_get_contents(SWTSA_JSON_DIR.'secret-words-'.$list_id.'.json'), true);
    }

    //Gets a users secret word list index
    public static function get_user_secret_word_list_index($user_id){
        return get_user_meta($user_id, 'swtsa_secret_word_list_index', true);
    }

    //Sets a users secret word list index
    public static function set_user_secret_word_list_index($user_id, $list_id){
        update_user_meta($user_id, 'swtsa_secret_word_list_index', $list_id);
    }

    //Get the hashed secret word of a user
    public static function get_user_secret_word($user_id){
        return get_user_meta($user_id, 'swtsa_secret_word', true);
    }

    //Sets a users secret word
    public static function set_user_secret_word($user_id, $word){
        update_user_meta($user_id, 'swtsa_secret_word', wp_hash_password($word));
    }

    //Tests a secret word
    public static function test_user_secret_word($user_id, $test_word){
        $wp_hasher = new PasswordHash(8, true);
        $pword_hashed = self::get_user_secret_word($user_id);
        if($wp_hasher->CheckPassword($test_word, $pword_hashed)){
            return true;
        }
        return false;
    }

    //Handle wordpress admin login
    private static function wordpress_admin_login(){
        add_action('wp_ajax_checkpassword', array('SWTSA_Users_Security', 'ajax_checkpassword'));
        add_action('wp_ajax_nopriv_checkpassword', array('SWTSA_Users_Security', 'ajax_checkpassword'));
        add_action('login_form', array('SWTSA_Users_Security', 'admin_login_page_form_add_secret_word_selector'));
        add_action('authenticate', array('SWTSA_Users_Security', 'authenticate_secret_word'), 30);
    }

    //Loads the additional form fields for the admin login page
    public static function admin_login_page_form_add_secret_word_selector(){
        ?>
            <p id="secret_word_paragraph">
                <label for="user_secret_word">Secret Word<br/>
                    <select name="sw" id="user_secret_word"></select>
                </label>
            </p>
        <?php
    }

    //Handle to authentication of a users secret wordpress
    public static function authenticate_secret_word($user, $front_end = false){
        if(isset($_POST['sw'])){
            if(!self::test_user_secret_word($user->ID, $_POST['sw'])){
                $error = new WP_Error();
                $error->add('secret_word_mismatch', '<strong>ERROR</strong> The secret word did not match for this user');
                if($front_end){
                    return false;
                }
                return $error;
            }
        }
        if($front_end){
            return true;
        }
        return $user;
    }

    //Handle a public facing login attempt
    public static function front_end_login_attempt($message = true, $sign_on = true){

        //Test to make sure we have all needed parts
        if(!isset($_POST['no-secret-word-registered'])){
            if(!isset($_POST['log']) || !isset($_POST['pwd']) || !isset($_POST['sw'])) {
                if(!$message){
                    return false;
                }
                return array('success' => false, 'message' => 'Please fill all fields');
            }
        } else {
            if(!isset($_POST['log']) || !isset($_POST['pwd'])) {
                if(!$message){
                    return false;
                }
                return array('success' => false, 'message' => 'Please fill all fields');
            }
        }

        //Test to see if username and password match
        $user = get_user_by('login', $_POST['log']);
        if(!is_a($user, 'WP_User')){
            $user = get_user_by('email', $_POST['log']);
        }
        if(!is_a($user, 'WP_User')){
            if(!$message){
                return false;
            }
            return array('success' => false, 'message' => 'Not a valid username or email');
        }
        if (!wp_check_password( $_POST['pwd'], $user->data->user_pass, $user->ID)){
            if(!$message){
                return false;
            }
            return array('success' => false, 'message' => 'You did not provide a matching username and password');
        }

        //Test to see if secret word matches
        if(!isset($_POST['no-secret-word-registered'])){
            if(!self::authenticate_secret_word($user, true)){
                if(!$message){
                    return false;
                }
                return array('success' => false, 'message' => 'You provided the wrong secret word');
            }
        }

        if($sign_on){
            wp_signon(array('user_login' => $user->user_login, 'user_password' => $_POST['pwd'], 'remember' => $_POST['rememberme']));
        }
        if(!$message){
            return true;
        }
        return array('success' => true, 'message' => 'Successful login');

    }

    //Checks password via ajax and echos out json results
    public static function ajax_checkpassword(){
        $user = get_user_by('login', $_POST['user']);
        if(!$user){
            $user = get_user_by('email', $_POST['user']);
            if(!$user){
                $user = swtsa_get_user_by_gamer_tag($_POST['user']);
                if(!$user){
                    echo json_encode(array('success' => false, 'message' => 'Username not valid!'));
                    die();
                }
            }
        }
        $pass = $_POST['password'];
        if (!wp_check_password( $pass, $user->data->user_pass, $user->ID)){
            echo json_encode(array('success' => false, 'message' => 'Username and password do not match!'));
            die();
        }
        if(isset($_POST['secret_words']) && $_POST['secret_words']){
            $has_secret_word = false;
            $list_id = false;
            if(self::get_user_secret_word($user->ID)){
                $has_secret_word = true;
                $list_id = self::get_user_secret_word_list_index($user->ID);
            }
            echo json_encode(array('success' => true, 'message' => 'Successful match!', 'has_secret_word' => $has_secret_word, 'secret_words' => self::get_secret_word_list($list_id)));
            die();
        }
        echo json_encode(array('success' => true, 'message' => 'Successful match!'));
        die();
    }

    //Handle the add/edit users on the portal
    private static function admin_user_management(){
        add_action('user_new_form', array('SWTSA_Users_Security', 'admin_user_page_form_add_secret_word_selector'));
        add_action('show_user_profile', array('SWTSA_Users_Security', 'admin_user_page_form_add_secret_word_selector'));
        add_action('edit_user_profile', array('SWTSA_Users_Security', 'admin_user_page_form_add_secret_word_selector'));
        add_action('edit_user_created_user', array('SWTSA_Users_Security', 'admin_save_secret_word_selector_form'));
        add_action('edit_user_profile_update', array('SWTSA_Users_Security', 'admin_save_secret_word_selector_form'));
        add_action('personal_options_update', array('SWTSA_Users_Security', 'admin_save_secret_word_selector_form'));
        add_action('admin_init', array('SWTSA_Users_Security', 'admin_force_two_step_authentication_setup'));
        add_action('after_password_reset', array('SWTSA_Users_Security', 'admin_clear_user_two_step_authenication'));
    }

    //Add secret word selector to register new user form
    public static function admin_user_page_form_add_secret_word_selector($data){
        if ( 'add-existing-user' == $data ) {
    		// $operation may also be 'add-existing-user'
    		return;
    	}

        if(is_a($data, 'WP_User')){
            $secret_word_index = SWTSA_Users_Security::get_user_secret_word_list_index($data->ID);
            $secret_word = SWTSA_Users_Security::get_user_secret_word($data->ID);
        }

        if(!$secret_word_index){
            $secret_word_index = ! empty( $_POST['swtsa_secret_word_list_index'] ) ? intval( $_POST['swtsa_secret_word_list_index'] ) : rand(1,9);
            $secret_word = ! empty( $_POST['swtsa_secret_word'] ) ? intval( $_POST['swtsa_secret_word'] ) : '';
        }

        $secret_word_list = SWTSA_Users_Security::get_secret_word_list($secret_word_index);

        if(is_a($data, 'WP_User')){
            foreach($secret_word_list as $sw){
                if(wp_check_password($sw, $secret_word)){
                    $secret_word = $sw;
                }
            }
        }

    	?>
    	<h3>Two-Step Authentication</h3>

    	<table class="form-table">
    		<tr>
    			<th><label for="swtsa_secret_word">Secret Word</label></th>
    			<td>
                    <input type="hidden" name="swtsa_secret_word_list_index" id="swtsa_secret_word_list_index" value="<?php echo $secret_word_index ?>" />
                    <select name="swtsa_secret_word" id="swtsa_secret_word">
                        <?php foreach($secret_word_list as $sw) : ?>
                            <option<?php if($sw == $secret_word) echo ' selected="selected"' ?>><?php echo $sw; ?></option>
                        <?php endforeach; ?>
                    </select>
    			</td>
    		</tr>
    	</table>
    	<?php
    }

    //Save the secret word field
    public static function admin_save_secret_word_selector_form($user_id){
        if(isset($_POST['swtsa_secret_word_list_index'])){
            SWTSA_Users_Security::set_user_secret_word_list_index($user_id, intval($_POST['swtsa_secret_word_list_index']));
        }
        if(isset($_POST['swtsa_secret_word'])){
            SWTSA_Users_Security::set_user_secret_word($user_id, $_POST['swtsa_secret_word']);
        }
    }

    //Forces two-step authentication setup if user doesn't have it setup in admin area
    public static function admin_force_two_step_authentication_setup(){
        global $pagenow;
        if(is_user_logged_in()){
            $user = wp_get_current_user();
            $secret_word = SWTSA_Users_Security::get_user_secret_word($user->ID);
            if(!$secret_word){
                if($pagenow !== 'profile.php'){
                    wp_redirect(get_edit_profile_url());
                    die();
                } else {
                    add_action('admin_notices', array('SWTSA_Users_Security', 'admin_area_no_secret_word_notice'));
                }
            }
        }
    }

    public static function admin_area_no_secret_word_notice(){
        ?>
        <div class="notice notice-error">
            <p>You must update your secret word at the bottom of this page before you can use the wordpress backend!</p>
        </div>
        <?php
    }

    public static function admin_clear_user_two_step_authenication($user){
        delete_user_meta($user->ID, 'swtsa_secret_word');
        delete_user_meta($user->ID, 'swtsa_secret_word_list_index');
    }

}

SWTSA_Users_Security::init();
