DELIMITER $$

CREATE PROCEDURE CreateUser(
    IN username VARCHAR(50),
    IN email VARCHAR(100)
)
BEGIN
    INSERT INTO User (username, email) VALUES (username, email);
END $$

DELIMITER ;