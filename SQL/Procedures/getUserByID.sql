DELIMITER $$

CREATE PROCEDURE GetUserById(IN input_user_id INT)
BEGIN
    SELECT * FROM User WHERE input_user_id = user_id;
END $$

DELIMITER ;