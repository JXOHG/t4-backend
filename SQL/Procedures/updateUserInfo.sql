DELIMITER $$

CREATE PROCEDURE UpdateUser(
    IN input_user_id INT,
    IN input_first_name VARCHAR(50),
    IN input_last_name VARCHAR(50),
    IN input_email VARCHAR(100)
)
BEGIN
    UPDATE User
    SET first_name = input_first_name, last_name = input_last_name, email = input_email
    WHERE user_id = input_user_id;
END $$

DELIMITER ;