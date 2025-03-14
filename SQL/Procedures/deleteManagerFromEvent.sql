DELIMITER $$

CREATE PROCEDURE RemoveManager(IN user_id INT, IN event_id INT)
BEGIN
    DELETE FROM Manages WHERE user_id = user_id AND event_id = event_id;
END $$

DELIMITER ;