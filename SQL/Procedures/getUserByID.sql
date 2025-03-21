DELIMITER $$

CREATE PROCEDURE GetUserById(IN user_id INT)
BEGIN
    SELECT * FROM User WHERE user_id = user_id;
END $$

DELIMITER ;