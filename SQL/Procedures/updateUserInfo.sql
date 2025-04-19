DELIMITER $$

CREATE PROCEDURE UpdateUser(
    IN p_user_id INT,
    IN p_first_name VARCHAR(50),
    IN p_last_name VARCHAR(50),
    IN p_email VARCHAR(100)
)
BEGIN
    UPDATE User
    SET first_name = p_first_name, 
        last_name = p_last_name, 
        email = p_email
    WHERE user_id = p_user_id;
END $$

DELIMITER ;