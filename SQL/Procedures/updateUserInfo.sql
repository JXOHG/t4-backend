DELIMITER $$

CREATE PROCEDURE UpdateUser(
    IN user_id INT,
    IN first_name VARCHAR(50),
    IN last_name VARCHAR(50),
    IN email VARCHAR(100)
)
BEGIN
    UPDATE User
    SET first_name = first_name, last_name = last_name, email = email
    WHERE user_id = user_id;
END $$

DELIMITER ;