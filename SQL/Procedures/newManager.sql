DELIMITER $$

CREATE PROCEDURE AssignManager(IN user_id INT, IN event_id INT)
BEGIN
    INSERT INTO Manages (user_id, event_id) VALUES (user_id, event_id);
END $$

DELIMITER ;